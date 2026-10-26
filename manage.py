"""Operator CLI. Admin rights are granted ONLY here (server-side, out-of-band), never over HTTP.

    python manage.py gen-env
    python manage.py create-admin <username>     # prompts for password (or ADMIN_PASSWORD env)
    python manage.py set-role <username> <user|admin>
"""
import getpass
import os
import secrets
import sys
import time

from app import validation
from app.config import load_config
from app.security import hash_password
from app.storage import DuplicateUsername, Storage


def gen_env():
    if os.path.exists(".env"):
        sys.exit(".env already exists; refusing to overwrite (it holds your pepper).")
    fd = os.open(".env", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(f"SERVER_PEPPER={secrets.token_hex(32)}\nDATABASE_PATH=records.db\n")
    print("Wrote .env (mode 600). Keep it out of git and back it up: losing the pepper "
          "invalidates every stored password hash.")


def create_admin(username: str):
    cfg = load_config()
    username = validation.normalize_username(username)
    if not validation.USERNAME_RE.fullmatch(username):
        sys.exit("invalid username")
    password = os.environ.get("ADMIN_PASSWORD") or getpass.getpass("Admin password: ")
    if not (validation.PASSWORD_MIN <= len(password) <= validation.PASSWORD_MAX):
        sys.exit(f"password must be {validation.PASSWORD_MIN}-{validation.PASSWORD_MAX} chars")
    store = Storage(cfg.database_path)
    try:
        store.create_user(username, hash_password(cfg, password), int(time.time()))
    except DuplicateUsername:
        pass  # existing user: just promote
    store.set_role(username, "admin")
    print(f"{username} is now an admin.")


def set_role(username: str, role: str):
    if role not in ("user", "admin"):
        sys.exit("role must be 'user' or 'admin'")
    store = Storage(load_config().database_path)
    print("ok" if store.set_role(validation.normalize_username(username), role) else "no such user")


if __name__ == "__main__":
    args = sys.argv[1:]
    if args[:1] == ["gen-env"]:
        gen_env()
    elif args[:1] == ["create-admin"] and len(args) == 2:
        create_admin(args[1])
    elif args[:1] == ["set-role"] and len(args) == 3:
        set_role(args[1], args[2])
    else:
        sys.exit(__doc__)
