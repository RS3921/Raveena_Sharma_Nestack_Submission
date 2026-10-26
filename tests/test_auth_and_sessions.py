from tests.conftest import PASSWORD, login, make_user, register


def test_register_login_happy_path(client):
    r = register(client, "Alice")
    assert r.status_code == 201
    assert r.get_json()["role"] == "user"
    assert r.get_json()["username"] == "alice"       # normalised
    r = login(client, "alice")
    assert r.status_code == 200
    assert len(r.get_json()["token"]) >= 40


def test_duplicate_username_conflict(client):
    register(client, "alice")
    assert register(client, "ALICE").status_code == 409


def test_bad_credentials_are_indistinguishable(client):
    register(client, "alice")
    wrong_pw = login(client, "alice", "not the password!")
    unknown = login(client, "nobody")
    assert wrong_pw.status_code == unknown.status_code == 401
    assert wrong_pw.get_json() == unknown.get_json()


def test_missing_invalid_and_tampered_tokens_get_401(client):
    h = make_user(client, "alice")
    token = h["Authorization"].split()[1]
    assert client.post("/records", json={"title": "a", "body": "b"}).status_code == 401
    flipped = token[:-1] + ("B" if token[-1] == "A" else "A")   # guaranteed different
    for bad in ["Bearer", "Bearer ", "Basic abc", f"Bearer {token}x", f"Bearer {flipped}",
                "Bearer " + "A" * 5000, "Bearer null", "bearer"]:
        r = client.get("/records/" + "0" * 32, headers={"Authorization": bad})
        assert r.status_code == 401, bad
    assert client.get("/records/" + "0" * 32, headers=h).status_code == 404  # real token works


def test_session_expires(client, clock, cfg):
    h = make_user(client, "alice")
    clock.advance(cfg.session_ttl_seconds - 1)
    assert client.get("/records/" + "0" * 32, headers=h).status_code == 404
    clock.advance(2)
    assert client.get("/records/" + "0" * 32, headers=h).status_code == 401


def test_logout_invalidates_token(client):
    h = make_user(client, "alice")
    assert client.post("/logout", headers=h).status_code == 204
    assert client.get("/records/" + "0" * 32, headers=h).status_code == 401


def test_sessions_are_unique_random(client):
    register(client, "alice")
    tokens = {login(client, "alice").get_json()["token"] for _ in range(5)}
    assert len(tokens) == 5
