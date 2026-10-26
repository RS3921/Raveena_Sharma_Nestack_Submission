import pytest

from app import create_app
from app.config import Config


class Clock:
    def __init__(self, t=1_700_000_000):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def cfg(tmp_path):
    # Cheap scrypt cost so the suite is fast; production defaults are in app/config.py.
    return Config(database_path=str(tmp_path / "test.db"), pepper=b"\x01" * 32,
                  scrypt_n=2 ** 4, scrypt_r=8, scrypt_p=1, max_body_bytes=4096)


@pytest.fixture
def app(cfg, clock):
    return create_app(cfg, clock=clock)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def store(app):
    return app.extensions["store"]


PASSWORD = "correct horse battery"


def register(client, username, password=PASSWORD, **extra):
    return client.post("/register", json={"username": username, "password": password, **extra})


def login(client, username, password=PASSWORD):
    return client.post("/login", json={"username": username, "password": password})


def make_user(client, username):
    assert register(client, username).status_code == 201
    r = login(client, username)
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.get_json()['token']}"}


def make_record(client, headers, title="t", body="b"):
    r = client.post("/records", json={"title": title, "body": body}, headers=headers)
    assert r.status_code == 201
    return r.get_json()["id"]


@pytest.fixture
def helpers():
    class H:
        pass
    h = H()
    h.register, h.login, h.make_user, h.make_record = register, login, make_user, make_record
    return h
