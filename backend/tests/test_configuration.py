"""Application defaults and database configuration."""

from src.core.config import Settings


def test_new_install_uses_socluma_database(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    settings = Settings(_env_file=None, USE_SQLITE=True, DATABASE_URL_OVERRIDE=None)
    assert settings.PROJECT_NAME == "Socluma"
    assert settings.MFA_ISSUER == "Socluma"
    assert settings.DATABASE_URL == "sqlite:///./socluma.db"


def test_unrelated_database_does_not_change_default(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "unrelated.db").touch()
    settings = Settings(_env_file=None, USE_SQLITE=True, DATABASE_URL_OVERRIDE=None)
    assert settings.DATABASE_URL == "sqlite:///./socluma.db"


def test_default_database_is_deterministic(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "unrelated.db").touch()
    (tmp_path / "socluma.db").touch()
    settings = Settings(_env_file=None, USE_SQLITE=True, DATABASE_URL_OVERRIDE=None)
    assert settings.DATABASE_URL == "sqlite:///./socluma.db"


def test_explicit_database_override_is_preserved(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "unrelated.db").touch()
    settings = Settings(
        _env_file=None, USE_SQLITE=True,
        DATABASE_URL_OVERRIDE="sqlite:///./custom.db",
    )
    assert settings.DATABASE_URL == "sqlite:///./custom.db"


def test_token_issuer_is_configurable():
    assert Settings(_env_file=None).JWT_ISSUER == "socluma"
    assert Settings(_env_file=None, JWT_ISSUER="custom-issuer").JWT_ISSUER == "custom-issuer"
