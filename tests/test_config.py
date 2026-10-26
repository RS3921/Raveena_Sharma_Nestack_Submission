import pytest

from app.config import ConfigError, load_config


def test_refuses_to_start_without_pepper(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)               # no .env here
    monkeypatch.delenv("SERVER_PEPPER", raising=False)
    with pytest.raises(ConfigError):
        load_config()


def test_rejects_short_or_non_hex_pepper(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    for bad in ["abcd", "zz" * 40]:
        monkeypatch.setenv("SERVER_PEPPER", bad)
        with pytest.raises(ConfigError):
            load_config()


def test_loads_valid_env(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SERVER_PEPPER", "ab" * 32)
    monkeypatch.setenv("MAX_FAILED_LOGINS", "3")
    cfg = load_config()
    assert cfg.max_failed_logins == 3 and len(cfg.pepper) == 32
