"""Accounts, sessions and lockout. Pure logic: no Flask imports."""
import logging
import time

from . import security, validation
from .config import Config
from .storage import DuplicateUsername, Storage

audit = logging.getLogger("audit")   # never log passwords or tokens


class InvalidCredentials(Exception):
    pass


class LockedOut(Exception):
    def __init__(self, retry_after: int):
        super().__init__("locked")
        self.retry_after = max(1, int(retry_after))


class UsernameTaken(Exception):
    pass


class AuthService:
    def __init__(self, cfg: Config, store: Storage, clock=time.time):
        self.cfg, self.store, self.clock = cfg, store, clock
        # Verified against when the username doesn't exist, so "unknown user" and
        # "wrong password" cost the same time (no user-enumeration timing oracle).
        self._dummy_hash = security.hash_password(cfg, "dummy-password-for-timing")

    def now(self) -> int:
        return int(self.clock())

    def register(self, username: str, password: str) -> str:
        pw_hash = security.hash_password(self.cfg, password)
        try:
            return self.store.create_user(username, pw_hash, self.now())
        except DuplicateUsername as exc:
            raise UsernameTaken() from exc

    def login(self, username: str, password: str):
        now = self.now()
        well_formed = bool(validation.USERNAME_RE.fullmatch(username))
        if well_formed:   # throttle per ACCOUNT NAME (exists or not), never per IP
            allowed, retry = self.store.reserve_login_attempt(
                username, now, self.cfg.max_failed_logins,
                self.cfg.lockout_seconds, self.cfg.failure_window_seconds)
            if not allowed:
                audit.warning("login_blocked_locked username=%r", username)
                raise LockedOut(retry)
        user = self.store.get_user_by_username(username) if well_formed else None
        stored = user["password_hash"] if user else self._dummy_hash
        ok = security.verify_password(self.cfg, password, stored)
        if not (ok and user):
            audit.warning("login_failed username=%r", username)
            raise InvalidCredentials()
        self.store.clear_login_attempts(username)
        # Return the bearer token once; only its hash is persisted in SQLite.
        token = security.new_session_token()
        expires_at = now + self.cfg.session_ttl_seconds
        self.store.create_session(security.hash_token(token), user["id"], now, expires_at)
        return token, self.cfg.session_ttl_seconds

    def authenticate(self, token: str):
        """Returns the user row or None. Expiry is enforced inside the query."""
        if not token or len(token) > 256:
            return None
        return self.store.get_session_user(security.hash_token(token), self.now())

    def logout(self, token: str) -> None:
        self.store.delete_session(security.hash_token(token))
