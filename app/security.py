"""Cryptographic primitives: password hashing and session tokens. Stdlib only."""
import base64
import hashlib
import hmac
import secrets

from .config import Config

_SALT_BYTES = 16
_KEY_BYTES = 32


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _prehash(pepper: bytes, password: str) -> bytes:
    # HMAC with a server-side pepper: a stolen DB alone cannot be cracked offline
    # without also stealing the pepper. Also normalises arbitrary-length input.
    return hmac.new(pepper, password.encode("utf-8"), hashlib.sha256).digest()


def _scrypt(secret: bytes, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(secret, salt=salt, n=n, r=r, p=p, dklen=_KEY_BYTES,
                          maxmem=2 * 128 * n * r + 1024 * 1024 * 4)


def hash_password(cfg: Config, password: str) -> str:
    """Return 'scrypt$N$r$p$salt$hash'. A fresh random per-user salt every call."""
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = _scrypt(_prehash(cfg.pepper, password), salt, cfg.scrypt_n, cfg.scrypt_r, cfg.scrypt_p)
    return "$".join(["scrypt", str(cfg.scrypt_n), str(cfg.scrypt_r), str(cfg.scrypt_p),
                     _b64(salt), _b64(digest)])


def verify_password(cfg: Config, password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, hash_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        actual = _scrypt(_prehash(cfg.pepper, password), salt, int(n), int(r), int(p))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)  # constant-time compare


def new_session_token() -> str:
    """256 bits from the OS CSPRNG. Opaque: carries no data and cannot be forged."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Only this hash is stored server-side, so a leaked DB yields no usable tokens.
    A fast hash is fine here because the input is 256 bits of entropy, not a password."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
