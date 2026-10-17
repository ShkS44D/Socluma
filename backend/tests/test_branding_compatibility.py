"""Protect existing installations while changing the display brand."""

from src.core.config import Settings


def test_new_install_uses_socluma_database(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    settings = Settings(_env_file=None, USE_SQLITE=True, DATABASE_URL_OVERRIDE=None)
    assert settings.PROJECT_NAME == "Socluma"
    assert settings.MFA_ISSUER == "Socluma"
    assert settings.DATABASE_URL == "sqlite:///./socluma.db"


def test_existing_database_remains_selected(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "vigilantai.db").touch()
    settings = Settings(_env_file=None, USE_SQLITE=True, DATABASE_URL_OVERRIDE=None)
    assert settings.DATABASE_URL == "sqlite:///./vigilantai.db"


def test_new_database_takes_precedence_when_both_exist(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "vigilantai.db").touch()
    (tmp_path / "socluma.db").touch()
    settings = Settings(_env_file=None, USE_SQLITE=True, DATABASE_URL_OVERRIDE=None)
    assert settings.DATABASE_URL == "sqlite:///./socluma.db"


def test_explicit_database_override_is_preserved(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "vigilantai.db").touch()
    settings = Settings(
        _env_file=None, USE_SQLITE=True,
        DATABASE_URL_OVERRIDE="sqlite:///./custom.db",
    )
    assert settings.DATABASE_URL == "sqlite:///./custom.db"


def test_default_token_issuer_remains_compatible():
    assert Settings(_env_file=None).JWT_ISSUER == "vigilantai"
