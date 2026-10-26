"""Environment-based configuration. No secrets live in the source tree."""
import os
from dataclasses import dataclass


class ConfigError(RuntimeError):
    pass


def load_dotenv(path: str = ".env") -> None:
    """Tiny .env loader (no dependency). Real environment variables win."""
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


@dataclass(frozen=True)
class Config:
    database_path: str
    pepper: bytes                       # server-side secret, NEVER stored in the DB
    session_ttl_seconds: int = 8 * 3600
    max_failed_logins: int = 5
    lockout_seconds: int = 15 * 60
    failure_window_seconds: int = 15 * 60
    max_body_bytes: int = 16 * 1024
    scrypt_n: int = 2 ** 15
    scrypt_r: int = 8
    scrypt_p: int = 3                   # OWASP-recommended scrypt parameter set


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if value <= 0:
        raise ConfigError(f"{name} must be positive")
    return value


def load_config() -> Config:
    load_dotenv()
    pepper_hex = os.environ.get("SERVER_PEPPER", "")
    try:
        pepper = bytes.fromhex(pepper_hex)
    except ValueError as exc:
        raise ConfigError("SERVER_PEPPER must be hex") from exc
    if len(pepper) < 32:
        raise ConfigError(
            "SERVER_PEPPER missing or too short (need >= 32 random bytes as hex). "
            "Run `python manage.py gen-env` to create a .env."
        )
    d = Config(database_path="", pepper=pepper)
    return Config(
        database_path=os.environ.get("DATABASE_PATH", "records.db"),
        pepper=pepper,
        session_ttl_seconds=_int("SESSION_TTL_SECONDS", d.session_ttl_seconds),
        max_failed_logins=_int("MAX_FAILED_LOGINS", d.max_failed_logins),
        lockout_seconds=_int("LOCKOUT_SECONDS", d.lockout_seconds),
        failure_window_seconds=_int("FAILURE_WINDOW_SECONDS", d.failure_window_seconds),
        max_body_bytes=_int("MAX_BODY_BYTES", d.max_body_bytes),
        scrypt_n=_int("SCRYPT_N", d.scrypt_n),
        scrypt_r=_int("SCRYPT_R", d.scrypt_r),
        scrypt_p=_int("SCRYPT_P", d.scrypt_p),
    )
