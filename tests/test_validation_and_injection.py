import pathlib
import re

from tests.conftest import make_user, register

SQLI = ["' OR '1'='1", "'; DROP TABLE users;--", "admin'--", "\" OR \"\"=\"", "1; SELECT * FROM users"]


def test_non_json_and_malformed_bodies_get_400(client):
    h = make_user(client, "alice")
    assert client.post("/register", data="username=a&password=b").status_code == 400
    assert client.post("/register", data="{not json", content_type="application/json").status_code == 400
    assert client.post("/register", data="", content_type="application/json").status_code == 400
    for body in ("[]", '"str"', "123", "null", "true"):
        assert client.post("/records", data=body, content_type="application/json",
                           headers=h).status_code == 400


def test_wrong_types_missing_and_unexpected_fields_get_400(client):
    h = make_user(client, "alice")
    bad = [{}, {"title": "x"}, {"body": "x"}, {"title": 1, "body": "x"}, {"title": "x", "body": None},
           {"title": ["x"], "body": "x"}, {"title": {"a": 1}, "body": "x"}, {"title": True, "body": "x"},
           {"title": "", "body": "x"}, {"title": "   ", "body": "x"}, {"title": "x", "body": ""},
           {"title": "x", "body": "y", "extra": 1}, {"title": "x\x00", "body": "y"}]
    for payload in bad:
        r = client.post("/records", json=payload, headers=h)
        assert r.status_code == 400, payload
    for payload in [{"username": 1, "password": "x" * 12}, {"username": "alice"},
                    {"username": "alice", "password": 123456789012}, {"username": "a", "password": "x" * 12},
                    {"username": "alice", "password": "short"}, {"username": ["a"], "password": "x" * 12}]:
        assert client.post("/register", json=payload).status_code == 400, payload
        assert client.post("/login", json=payload).status_code in (400, 401, 429)


def test_length_limits(client):
    h = make_user(client, "alice")
    assert client.post("/records", json={"title": "t" * 201, "body": "b"}, headers=h).status_code == 400
    assert client.post("/records", json={"title": "t" * 200, "body": "b" * 10_000},
                       headers=h).status_code in (201, 400)   # 10k body < 4096-byte test cap -> 400
    assert client.post("/register", json={"username": "u" * 33, "password": "p" * 12}).status_code == 400
    assert client.post("/register", json={"username": "alice2", "password": "p" * 129}).status_code == 400


def test_oversized_body_gets_400_not_413_or_500(client):
    h = make_user(client, "alice")
    r = client.post("/records", json={"title": "x", "body": "A" * 50_000}, headers=h)
    assert r.status_code == 400 and r.get_json()["error"] == "payload_too_large"
    r = client.post("/register", data=b"{" + b"x" * 100_000, content_type="application/json")
    assert r.status_code == 400


def test_unexpected_exception_returns_generic_500_without_stack_trace(app, client, store, monkeypatch):
    h = make_user(client, "alice")

    def boom(*a, **k):
        raise RuntimeError("secret internals /srv/app/storage.py")
    monkeypatch.setattr(store, "get_record", boom)
    r = client.get("/records/" + "a" * 32, headers=h)
    assert r.status_code == 500
    assert r.get_json() == {"error": "internal_error", "message": "Internal server error"}
    assert b"Traceback" not in r.data and b"secret internals" not in r.data


def test_unknown_routes_and_methods_return_json(client):
    assert client.get("/nope").status_code == 404
    assert client.get("/nope").is_json
    assert client.get("/register").status_code == 405


def test_sql_injection_in_credentials_and_ids(client):
    register(client, "alice")
    for payload in SQLI:
        assert client.post("/register", json={"username": payload, "password": "p" * 12}).status_code == 400
        r = client.post("/login", json={"username": payload, "password": payload})
        assert r.status_code in (400, 401)
    h = make_user(client, "bob")
    for payload in SQLI + ["1 OR 1=1", "%27%20OR%201%3D1"]:
        assert client.get(f"/records/{payload}", headers=h).status_code == 404


def test_sql_metacharacters_in_record_text_are_stored_literally(client):
    h = make_user(client, "alice")
    title, body = "'; DROP TABLE records;--", "Robert'); DROP TABLE users;--"
    rid = client.post("/records", json={"title": title, "body": body}, headers=h).get_json()["id"]
    r = client.get(f"/records/{rid}", headers=h).get_json()
    assert r["title"] == title and r["body"] == body
    assert client.get("/records/" + "0" * 32, headers=h).status_code == 404  # tables intact


def test_no_string_built_sql_in_storage_layer():
    src = (pathlib.Path(__file__).parent.parent / "app" / "storage.py").read_text()
    for call in re.findall(r"\.execute\((.*?)\n\s*(?:\)|[a-z_]+ =|with|return|conn)", src, re.S):
        assert not re.search(r'\bf["\']', call), call
        assert ".format(" not in call and "%s" not in call
    assert not re.search(r'execute\(\s*f["\']', src)
    assert not re.search(r'execute\([^)]*"\s*\+', src)


def test_responses_have_security_headers(client):
    r = client.get("/nope")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Cache-Control"] == "no-store"
