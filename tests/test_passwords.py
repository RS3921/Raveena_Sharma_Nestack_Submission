import sqlite3

from app import security
from tests.conftest import PASSWORD, register


def test_hash_is_scrypt_salted_and_not_plaintext(cfg):
    h1 = security.hash_password(cfg, PASSWORD)
    h2 = security.hash_password(cfg, PASSWORD)
    assert h1.startswith("scrypt$")
    assert PASSWORD not in h1
    assert h1 != h2                                   # per-user random salt
    assert security.verify_password(cfg, PASSWORD, h1)
    assert not security.verify_password(cfg, "wrong password!!", h1)


def test_verify_rejects_garbage_hashes(cfg):
    for bad in ["", "plaintext", "md5$abc$def", "scrypt$x$y$z$a$b", "scrypt$16$8$1$!!$!!"]:
        assert not security.verify_password(cfg, PASSWORD, bad)


def test_pepper_is_required_to_verify(cfg):
    from dataclasses import replace
    h = security.hash_password(cfg, PASSWORD)
    other = replace(cfg, pepper=b"\x02" * 32)
    assert not security.verify_password(other, PASSWORD, h)


def test_database_never_contains_plaintext_password(client, cfg):
    register(client, "alice")
    raw = open(cfg.database_path, "rb").read()
    assert PASSWORD.encode() not in raw
    row = sqlite3.connect(cfg.database_path).execute(
        "SELECT password_hash FROM users WHERE username='alice'").fetchone()
    assert row[0].startswith("scrypt$")


def test_session_tokens_stored_only_as_hashes(client, cfg, helpers):
    headers = helpers.make_user(client, "alice")
    token = headers["Authorization"].split()[1]
    rows = sqlite3.connect(cfg.database_path).execute("SELECT token_hash FROM sessions").fetchall()
    assert rows and all(token not in r[0] for r in rows)
    assert rows[0][0] == security.hash_token(token)
