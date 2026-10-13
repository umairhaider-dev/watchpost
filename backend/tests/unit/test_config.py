from __future__ import annotations

import logging
from typing import Any

import pytest
from pydantic import ValidationError

from watchpost.core.config import Environment, Settings, log_configuration_warnings

GOOD_SECRET = "x" * 40


def make_settings(**kwargs: Any) -> Settings:
    """Build settings from keyword arguments only, ignoring any local .env file."""
    return Settings(_env_file=None, **kwargs)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "WATCHPOST_ENV",
        "WATCHPOST_SECRET_KEY",
        "WATCHPOST_CORS_ORIGINS",
        "WATCHPOST_DATABASE_URL",
        "WATCHPOST_LOG_LEVEL",
    ):
        monkeypatch.delenv(name, raising=False)


def test_defaults_are_usable_in_development() -> None:
    settings = make_settings(secret_key=GOOD_SECRET)

    assert settings.env is Environment.DEVELOPMENT
    assert not settings.is_production
    assert settings.database_url.scheme == "postgresql+asyncpg"
    assert settings.cors_origins == ["http://localhost:3000", "http://localhost:5173"]


def test_missing_secret_in_development_generates_one(caplog: pytest.LogCaptureFixture) -> None:
    settings = make_settings()

    assert settings.secret_key is not None
    assert len(settings.secret_key.get_secret_value()) >= 32
    assert settings.secret_key_generated

    with caplog.at_level(logging.WARNING, logger="watchpost.core.config"):
        log_configuration_warnings(settings)
    assert "WATCHPOST_SECRET_KEY is not set" in caplog.text


def test_configured_secret_produces_no_warning(caplog: pytest.LogCaptureFixture) -> None:
    settings = make_settings(secret_key=GOOD_SECRET)

    with caplog.at_level(logging.WARNING, logger="watchpost.core.config"):
        log_configuration_warnings(settings)

    assert not settings.secret_key_generated
    assert caplog.text == ""


def test_blank_secret_is_treated_as_missing() -> None:
    settings = make_settings(secret_key="   ")

    assert settings.secret_key is not None
    assert settings.secret_key.get_secret_value().strip() != ""


def test_production_requires_secret_key() -> None:
    with pytest.raises(ValidationError, match="must be set in production"):
        make_settings(env="production")


def test_production_accepts_strong_secret() -> None:
    settings = make_settings(env="production", secret_key=GOOD_SECRET)

    assert settings.is_production


def test_short_secret_is_rejected() -> None:
    with pytest.raises(ValidationError, match="at least 32 characters"):
        make_settings(secret_key="too-short")


def test_secret_is_not_leaked_in_repr() -> None:
    settings = make_settings(secret_key=GOOD_SECRET)

    assert GOOD_SECRET not in repr(settings)


def test_cors_origins_parsed_from_comma_separated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WATCHPOST_CORS_ORIGINS", "https://soc.example.org/, http://localhost:3000")

    settings = make_settings(secret_key=GOOD_SECRET)

    assert settings.cors_origins == ["https://soc.example.org", "http://localhost:3000"]


def test_wildcard_cors_origin_is_rejected() -> None:
    with pytest.raises(ValidationError, match="wildcard"):
        make_settings(secret_key=GOOD_SECRET, cors_origins="*")


def test_database_url_must_use_asyncpg() -> None:
    with pytest.raises(ValidationError, match="postgresql\\+asyncpg"):
        make_settings(secret_key=GOOD_SECRET, database_url="postgresql://u:p@db:5432/watchpost")


def test_log_level_is_case_insensitive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WATCHPOST_LOG_LEVEL", "debug")

    settings = make_settings(secret_key=GOOD_SECRET)

    assert settings.log_level == "DEBUG"


def test_unknown_environment_is_rejected() -> None:
    with pytest.raises(ValidationError):
        make_settings(env="staging", secret_key=GOOD_SECRET)
