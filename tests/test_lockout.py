import threading

from tests.conftest import PASSWORD, login, register


def test_locks_after_five_failures_with_429(client):
    register(client, "alice")
    codes = [login(client, "alice", "wrong-password-x").status_code for _ in range(5)]
    assert codes == [401] * 5
    r = login(client, "alice", "wrong-password-x")
    assert r.status_code == 429
    assert int(r.headers["Retry-After"]) > 0


def test_correct_password_is_refused_while_locked(client):
    register(client, "alice")
    for _ in range(5):
        login(client, "alice", "wrong-password-x")
    assert login(client, "alice", PASSWORD).status_code == 429   # attacker can't keep guessing


def test_lock_is_per_account_not_per_ip(client):
    register(client, "alice")
    register(client, "bob")
    for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"):
        r = client.post("/login", json={"username": "alice", "password": "wrong-password-x"},
                        environ_overrides={"REMOTE_ADDR": ip})
        assert r.status_code == 401
    # a brand-new IP is still blocked for alice...
    r = client.post("/login", json={"username": "alice", "password": PASSWORD},
                    environ_overrides={"REMOTE_ADDR": "9.9.9.9"})
    assert r.status_code == 429
    # ...while bob, from the attacker's IP, is unaffected.
    r = client.post("/login", json={"username": "bob", "password": PASSWORD},
                    environ_overrides={"REMOTE_ADDR": "1.1.1.1"})
    assert r.status_code == 200


def test_unknown_usernames_are_throttled_identically(client):
    codes = [login(client, "ghost", "wrong-password-x").status_code for _ in range(6)]
    assert codes == [401] * 5 + [429]      # no enumeration via lockout behaviour


def test_lock_expires(client, clock, cfg):
    register(client, "alice")
    for _ in range(5):
        login(client, "alice", "wrong-password-x")
    assert login(client, "alice", PASSWORD).status_code == 429
    clock.advance(cfg.lockout_seconds + 1)
    assert login(client, "alice", PASSWORD).status_code == 200


def test_success_resets_the_counter(client):
    register(client, "alice")
    for _ in range(4):
        login(client, "alice", "wrong-password-x")
    assert login(client, "alice", PASSWORD).status_code == 200
    for _ in range(4):
        assert login(client, "alice", "wrong-password-x").status_code == 401
    assert login(client, "alice", PASSWORD).status_code == 200


def test_old_failures_age_out_of_window(client, clock, cfg):
    register(client, "alice")
    for _ in range(4):
        login(client, "alice", "wrong-password-x")
    clock.advance(cfg.failure_window_seconds + 1)
    for _ in range(4):
        assert login(client, "alice", "wrong-password-x").status_code == 401


def test_parallel_guessing_cannot_beat_the_limit(app):
    register(app.test_client(), "alice")
    codes, lock = [], threading.Lock()

    def attempt():
        r = app.test_client().post("/login", json={"username": "alice", "password": "wrong-password-x"})
        with lock:
            codes.append(r.status_code)

    threads = [threading.Thread(target=attempt) for _ in range(25)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert codes.count(401) == 5          # exactly the allowance, never more
    assert codes.count(429) == 20


def test_audit_log_escapes_attacker_controlled_usernames(client, caplog):
    import logging
    with caplog.at_level(logging.WARNING, logger="audit"):
        login(client, "evil\nFAKE LOG LINE: admin logged in")
    assert "\n" not in caplog.records[0].getMessage()   # no log forging
