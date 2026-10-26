"""SQLite storage. EVERY query is parameterised (`?` placeholders): no string-built SQL."""
import contextlib
import sqlite3
import uuid

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS records (
    id         TEXT PRIMARY KEY,
    owner_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title      TEXT NOT NULL,
    body       TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_records_owner ON records(owner_id);
-- Keyed by username (not IP, not user id) so unknown usernames are throttled
-- identically to real ones and lockout state leaks nothing about account existence.
CREATE TABLE IF NOT EXISTS login_attempts (
    username     TEXT PRIMARY KEY,
    failures     INTEGER NOT NULL,
    window_start INTEGER NOT NULL,
    locked_until INTEGER NOT NULL DEFAULT 0
);
"""


class DuplicateUsername(Exception):
    pass


class Storage:
    def __init__(self, path: str):
        self.path = path
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.executescript(SCHEMA)

    @contextlib.contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.path, timeout=10, isolation_level=None)  # autocommit
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
        finally:
            conn.close()

    # ---- users -----------------------------------------------------------
    def create_user(self, username: str, password_hash: str, now: int) -> str:
        """Always creates role='user'. There is deliberately no role parameter."""
        user_id = uuid.uuid4().hex
        try:
            with self._conn() as conn:
                conn.execute(
                    "INSERT INTO users (id, username, password_hash, role, created_at) "
                    "VALUES (?, ?, ?, 'user', ?)",
                    (user_id, username, password_hash, now),
                )
        except sqlite3.IntegrityError as exc:
            raise DuplicateUsername(username) from exc
        return user_id

    def get_user_by_username(self, username: str):
        with self._conn() as conn:
            return conn.execute(
                "SELECT id, username, password_hash, role FROM users WHERE username = ?",
                (username,),
            ).fetchone()

    def set_role(self, username: str, role: str) -> bool:
        """Operator-only (used by manage.py). Never imported by the HTTP layer."""
        with self._conn() as conn:
            cur = conn.execute("UPDATE users SET role = ? WHERE username = ?", (role, username))
            return cur.rowcount == 1

    # ---- sessions --------------------------------------------------------
    def create_session(self, token_hash: str, user_id: str, now: int, expires_at: int) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
            conn.execute(
                "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                (token_hash, user_id, now, expires_at),
            )

    def get_session_user(self, token_hash: str, now: int):
        """Role is read from the users table on EVERY request, so demotion is immediate."""
        with self._conn() as conn:
            return conn.execute(
                "SELECT u.id AS id, u.username AS username, u.role AS role "
                "FROM sessions s JOIN users u ON u.id = s.user_id "
                "WHERE s.token_hash = ? AND s.expires_at > ?",
                (token_hash, now),
            ).fetchone()

    def delete_session(self, token_hash: str) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))

    # ---- records ---------------------------------------------------------
    def create_record(self, owner_id: str, title: str, body: str, now: int) -> str:
        record_id = uuid.uuid4().hex  # random, non-enumerable
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO records (id, owner_id, title, body, created_at) VALUES (?, ?, ?, ?, ?)",
                (record_id, owner_id, title, body, now),
            )
        return record_id

    def get_record(self, record_id: str):
        with self._conn() as conn:
            return conn.execute(
                "SELECT id, owner_id, title, body, created_at FROM records WHERE id = ?",
                (record_id,),
            ).fetchone()

    # ---- login throttling ------------------------------------------------
    def reserve_login_attempt(self, username: str, now: int, max_failures: int,
                              lockout_seconds: int, window_seconds: int):
        """Atomically spend one attempt BEFORE the password is checked.

        Reserving up front (inside BEGIN IMMEDIATE) means N parallel guesses cannot
        all slip past a 'check, then verify, then increment' race. A successful
        login clears the counter. Returns (allowed, retry_after_seconds).
        """
        with self._conn() as conn:
            # Serialize the counter read and reservation before password verification.
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT failures, window_start, locked_until FROM login_attempts WHERE username = ?",
                    (username,),
                ).fetchone()
                if row and row["locked_until"] > now:
                    conn.execute("COMMIT")
                    return False, row["locked_until"] - now
                if (row is None or row["locked_until"] > 0
                        or now - row["window_start"] >= window_seconds):
                    failures, window_start = 0, now          # fresh window
                else:
                    failures, window_start = row["failures"], row["window_start"]
                failures += 1
                locked_until = now + lockout_seconds if failures >= max_failures else 0
                conn.execute(
                    "INSERT INTO login_attempts (username, failures, window_start, locked_until) "
                    "VALUES (?, ?, ?, ?) ON CONFLICT(username) DO UPDATE SET "
                    "failures = excluded.failures, window_start = excluded.window_start, "
                    "locked_until = excluded.locked_until",
                    (username, failures, window_start, locked_until),
                )
                conn.execute("DELETE FROM login_attempts WHERE locked_until < ? "
                             "AND window_start < ?", (now, now - window_seconds))
                conn.execute("COMMIT")
                return True, 0
            except Exception:
                conn.execute("ROLLBACK")
                raise

    def clear_login_attempts(self, username: str) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM login_attempts WHERE username = ?", (username,))
