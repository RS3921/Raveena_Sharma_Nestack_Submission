"""Strict input validation. Every failure is a ValidationError -> clean 400, never a 500."""
import re

USERNAME_RE = re.compile(r"[a-z0-9_.-]{3,32}")
RECORD_ID_RE = re.compile(r"[0-9a-f]{32}")

USERNAME_MAX = 32
PASSWORD_MIN = 12
PASSWORD_MAX = 128
TITLE_MAX = 200
BODY_MAX = 10_000

# Any attempt to smuggle a privilege field is an escalation attempt -> 403.
PRIVILEGE_FIELDS = {
    "role", "roles", "is_admin", "isadmin", "admin", "is_staff", "is_superuser",
    "superuser", "permissions", "scope", "scopes", "user_type", "usertype", "group", "groups",
}

# A tiny deny-list of the worst offenders; real deployments should use a breached-password check.
COMMON_PASSWORDS = {
    "password1234", "passwordpassword", "123456789012", "qwertyuiop12", "letmein123456",
    "administrator", "iloveyou12345", "welcome12345", "changeme1234",
}


class ValidationError(Exception):
    status = 400

    def __init__(self, message: str, code: str = "invalid_input"):
        super().__init__(message)
        self.message = message
        self.code = code


class PrivilegeEscalationAttempt(Exception):
    status = 403


def parse_json_object(request, max_bytes: int) -> dict:
    if request.content_length is not None and request.content_length > max_bytes:
        raise ValidationError("Request body too large", "payload_too_large")
    if not request.is_json:
        raise ValidationError("Content-Type must be application/json", "invalid_content_type")
    data = request.get_json(silent=True)
    if data is None and not request.get_data(cache=True):
        raise ValidationError("Request body is required", "missing_body")
    if not isinstance(data, dict):
        raise ValidationError("Body must be a JSON object", "invalid_json")
    return data


def reject_privilege_fields(data: dict) -> None:
    if any(isinstance(k, str) and k.lower() in PRIVILEGE_FIELDS for k in data):
        raise PrivilegeEscalationAttempt()


def require_only(data: dict, allowed: set) -> None:
    extra = set(data) - allowed
    if extra:
        raise ValidationError("Unexpected field(s)", "unexpected_field")


def _string(data: dict, field: str, min_len: int, max_len: int, strip: bool = False) -> str:
    if field not in data:
        raise ValidationError(f"'{field}' is required", "missing_field")
    value = data[field]
    if not isinstance(value, str):          # rejects numbers, bools, null, lists, objects
        raise ValidationError(f"'{field}' must be a string", "wrong_type")
    if "\x00" in value:
        raise ValidationError(f"'{field}' contains invalid characters", "invalid_chars")
    if strip:
        value = value.strip()
    if len(value) < min_len:
        raise ValidationError(f"'{field}' must be at least {min_len} character(s)", "too_short")
    if len(value) > max_len:
        raise ValidationError(f"'{field}' must be at most {max_len} characters", "too_long")
    return value


def normalize_username(raw: str) -> str:
    return raw.strip().lower()


def validate_register(data: dict):
    require_only(data, {"username", "password"})
    username = normalize_username(_string(data, "username", 1, USERNAME_MAX + 8))
    if not USERNAME_RE.fullmatch(username):
        raise ValidationError("username must be 3-32 chars of a-z, 0-9, '_', '.', '-'", "invalid_username")
    password = _string(data, "password", PASSWORD_MIN, PASSWORD_MAX)
    if password.lower() in COMMON_PASSWORDS or password.lower() == username:
        raise ValidationError("password is too common", "weak_password")
    return username, password


def validate_login(data: dict):
    require_only(data, {"username", "password"})
    username = normalize_username(_string(data, "username", 1, USERNAME_MAX + 8))
    password = _string(data, "password", 1, PASSWORD_MAX)
    return username, password


def validate_record(data: dict):
    require_only(data, {"title", "body"})
    title = _string(data, "title", 1, TITLE_MAX, strip=True)
    body = _string(data, "body", 1, BODY_MAX)
    return title, body
