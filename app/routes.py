"""HTTP layer only: parse -> validate -> call service -> shape response."""
import functools
import logging

from flask import Blueprint, current_app, g, jsonify, request

from . import access, validation
from .auth import InvalidCredentials, LockedOut, UsernameTaken

bp = Blueprint("api", __name__)
audit = logging.getLogger("audit")


def error(status: int, code: str, message: str = "", headers: dict | None = None):
    resp = jsonify({"error": code, "message": message or code})
    resp.status_code = status
    for k, v in (headers or {}).items():
        resp.headers[k] = v
    return resp


def _auth():
    return current_app.extensions["auth"]


def _store():
    return current_app.extensions["store"]


def _bearer_token():
    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def require_auth(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        token = _bearer_token()
        user = _auth().authenticate(token) if token else None
        if user is None:
            return error(401, "unauthorized", "Valid session required",
                         {"WWW-Authenticate": "Bearer"})
        # The principal comes from the verified server-side session, never request JSON.
        g.user, g.token = user, token
        return view(*args, **kwargs)
    return wrapper


def _json_body():
    return validation.parse_json_object(request, current_app.config["MAX_BODY_BYTES"])


@bp.post("/register")
def register():
    data = _json_body()
    validation.reject_privilege_fields(data)      # role can NEVER come from the client
    username, password = validation.validate_register(data)
    try:
        user_id = _auth().register(username, password)
    except UsernameTaken:
        return error(409, "username_taken", "Username already taken")
    return jsonify({"id": user_id, "username": username, "role": "user"}), 201


@bp.post("/login")
def login():
    data = _json_body()
    validation.reject_privilege_fields(data)
    username, password = validation.validate_login(data)
    try:
        token, ttl = _auth().login(username, password)
    except LockedOut as exc:
        return error(429, "too_many_attempts", "Too many failed attempts; try again later",
                     {"Retry-After": str(exc.retry_after)})
    except InvalidCredentials:
        return error(401, "invalid_credentials", "Invalid username or password")
    return jsonify({"token": token, "token_type": "Bearer", "expires_in": ttl}), 200


@bp.post("/logout")
@require_auth
def logout():
    _auth().logout(g.token)
    return "", 204


@bp.post("/records")
@require_auth
def create_record():
    data = _json_body()
    validation.reject_privilege_fields(data)
    title, body = validation.validate_record(data)
    record_id = _store().create_record(g.user["id"], title, body, _auth().now())
    return jsonify({"id": record_id}), 201


@bp.get("/records/<record_id>")
@require_auth
def read_record(record_id: str):
    record = None
    if validation.RECORD_ID_RE.fullmatch(record_id):
        record = _store().get_record(record_id)
    if record is None or not access.can_read_record(g.user, record):
        if record is not None:
            audit.warning("access_denied user=%s record=%s", g.user["id"], record_id)
        # Keep missing and unowned IDs indistinguishable so IDs cannot be probed.
        return error(404, "not_found", "Record not found")
    return jsonify({
        "id": record["id"],
        "title": record["title"],
        "body": record["body"],
        "owner_id": record["owner_id"],
        "created_at": record["created_at"],
    }), 200
