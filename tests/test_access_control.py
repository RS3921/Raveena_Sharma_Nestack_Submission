import sqlite3

from tests.conftest import make_record, make_user, register


def test_owner_can_read_own_record(client):
    a = make_user(client, "alice")
    rid = make_record(client, a, "T", "secret body")
    r = client.get(f"/records/{rid}", headers=a)
    assert r.status_code == 200
    assert r.get_json()["title"] == "T" and r.get_json()["body"] == "secret body"


def test_other_user_cannot_read_record(client):
    a, b = make_user(client, "alice"), make_user(client, "bob")
    rid = make_record(client, a, "T", "alice-only-secret")
    r = client.get(f"/records/{rid}", headers=b)
    assert r.status_code in (403, 404)
    assert b"alice-only-secret" not in r.data


def test_forbidden_and_missing_are_indistinguishable(client):
    a, b = make_user(client, "alice"), make_user(client, "bob")
    rid = make_record(client, a)
    denied = client.get(f"/records/{rid}", headers=b)
    missing = client.get("/records/" + "f" * 32, headers=b)
    assert denied.status_code == missing.status_code == 404
    assert denied.get_json() == missing.get_json()   # no existence oracle


def test_unauthenticated_cannot_read(client):
    a = make_user(client, "alice")
    rid = make_record(client, a)
    assert client.get(f"/records/{rid}").status_code == 401


def test_admin_can_read_any_record(client, store):
    a, admin = make_user(client, "alice"), make_user(client, "root")
    rid = make_record(client, a, "T", "body")
    assert client.get(f"/records/{rid}", headers=admin).status_code == 404  # not admin yet
    assert store.set_role("root", "admin")
    r = client.get(f"/records/{rid}", headers=admin)    # same session, role re-read from DB
    assert r.status_code == 200 and r.get_json()["body"] == "body"


def test_demotion_takes_effect_immediately(client, store):
    a, admin = make_user(client, "alice"), make_user(client, "root")
    rid = make_record(client, a)
    store.set_role("root", "admin")
    assert client.get(f"/records/{rid}", headers=admin).status_code == 200
    store.set_role("root", "user")
    assert client.get(f"/records/{rid}", headers=admin).status_code == 404


def test_record_ids_are_random_not_sequential(client):
    a = make_user(client, "alice")
    ids = [make_record(client, a) for _ in range(5)]
    assert len(set(ids)) == 5 and all(len(i) == 32 for i in ids)


def test_owner_is_taken_from_session_not_body(client):
    a, b = make_user(client, "alice"), make_user(client, "bob")
    r = client.post("/records", json={"title": "x", "body": "y", "owner_id": "someone"}, headers=b)
    assert r.status_code in (400, 403)


# ---- privilege escalation ------------------------------------------------
def test_register_with_role_field_is_forbidden_and_creates_nothing(client, cfg):
    for field, val in [("role", "admin"), ("is_admin", True), ("Role", "admin"), ("isAdmin", True)]:
        r = register(client, "mallory", **{field: val})
        assert r.status_code == 403, field
    n = sqlite3.connect(cfg.database_path).execute("SELECT COUNT(*) FROM users").fetchone()[0]
    assert n == 0


def test_registered_accounts_are_always_plain_users(client, cfg):
    register(client, "alice")
    role = sqlite3.connect(cfg.database_path).execute(
        "SELECT role FROM users WHERE username='alice'").fetchone()[0]
    assert role == "user"


def test_record_endpoint_rejects_role_fields(client):
    a = make_user(client, "alice")
    r = client.post("/records", json={"title": "x", "body": "y", "role": "admin"}, headers=a)
    assert r.status_code == 403


def test_http_layer_has_no_way_to_set_roles():
    import pathlib
    for name in ("routes.py", "auth.py", "validation.py", "__init__.py"):
        src = (pathlib.Path(__file__).parent.parent / "app" / name).read_text()
        assert "set_role" not in src, name
