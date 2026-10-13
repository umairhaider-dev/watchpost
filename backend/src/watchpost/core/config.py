"""Application settings loaded from environment variables.

Every setting is read from a ``WATCHPOST_``-prefixed environment variable
(for example ``WATCHPOST_DATABASE_URL``). A ``.env`` file in the working
directory is also honoured, which keeps local development simple while
production deployments inject real values through the environment.
"""

from __future__ import annotations

import logging
import secrets
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import (
    Field,
    PostgresDsn,
    PrivateAttr,
    RedisDsn,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

logger = logging.getLogger(__name__)

MIN_SECRET_KEY_LENGTH = 32


class Environment(StrEnum):
    """Deployment environment the process is running in."""

    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """Runtime configuration for the API and the worker."""

    model_config = SettingsConfigDict(
        env_prefix="WATCHPOST_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    env: Environment = Environment.DEVELOPMENT
    database_url: PostgresDsn = Field(
        default=PostgresDsn("postgresql+asyncpg://watchpost:watchpost@localhost:5432/watchpost"),
        description="SQLAlchemy URL; must use the asyncpg driver.",
    )
    database_pool_size: int = Field(default=10, ge=1, le=100)
    database_echo: bool = False
    redis_url: RedisDsn = RedisDsn("redis://localhost:6379/0")
    secret_key: SecretStr | None = Field(
        default=None,
        description="Key used to sign session tokens. Required in production.",
    )
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_format: Literal["text", "json"] = "text"
    cors_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:3000", "http://localhost:5173"],
    )

    # Detection
    rules_dir: Path = Field(
        default=Path("rules"),
        description="Folder with the built-in rule YAML files, loaded by `watchpost sync-rules`.",
    )

    # Ingestion
    upload_dir: Path = Field(
        default=Path("data/uploads"),
        description="Where uploaded files wait for the worker. Must be shared by api and worker.",
    )
    keep_uploads: bool = Field(
        default=False, description="Keep uploaded files after ingestion instead of deleting them."
    )
    max_upload_bytes: int = Field(default=512 * 1024 * 1024, ge=1024)
    ingest_batch_size: int = Field(default=2000, ge=100, le=20_000)
    watch_enabled: bool = True
    watch_dir: Path = Field(
        default=Path("data/watch"),
        description="Folder the worker scans for new log files (read-only access is enough).",
    )
    watch_interval_seconds: int = Field(default=10, ge=5, le=60)
    watch_settle_seconds: int = Field(
        default=5,
        ge=0,
        le=300,
        description="Ignore files modified more recently than this, as they may still be written.",
    )

    _secret_key_generated: bool = PrivateAttr(default=False)

    @field_validator("database_url")
    @classmethod
    def _require_asyncpg_driver(cls, value: PostgresDsn) -> PostgresDsn:
        if value.scheme != "postgresql+asyncpg":
            msg = "database_url must use the 'postgresql+asyncpg' scheme"
            raise ValueError(msg)
        return value

    @field_validator("log_level", mode="before")
    @classmethod
    def _normalise_log_level(cls, value: object) -> object:
        return value.upper() if isinstance(value, str) else value

    @field_validator("secret_key", mode="before")
    @classmethod
    def _blank_secret_is_unset(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        """Accept a comma-separated string as well as a JSON-style list."""
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    @field_validator("cors_origins")
    @classmethod
    def _reject_wildcard_origin(cls, value: list[str]) -> list[str]:
        if "*" in value:
            msg = "wildcard CORS origins are not allowed; list each origin explicitly"
            raise ValueError(msg)
        return [origin.rstrip("/") for origin in value]

    @model_validator(mode="after")
    def _check_secret_key(self) -> Settings:
        if self.secret_key is None:
            if self.env is Environment.PRODUCTION:
                msg = "WATCHPOST_SECRET_KEY must be set in production"
                raise ValueError(msg)
            self.secret_key = SecretStr(secrets.token_urlsafe(48))
            self._secret_key_generated = True
        elif len(self.secret_key.get_secret_value()) < MIN_SECRET_KEY_LENGTH:
            msg = f"WATCHPOST_SECRET_KEY must be at least {MIN_SECRET_KEY_LENGTH} characters"
            raise ValueError(msg)
        return self

    @property
    def is_production(self) -> bool:
        """True when running with production hardening enabled."""
        return self.env is Environment.PRODUCTION

    @property
    def secret_key_generated(self) -> bool:
        """True when no secret key was configured and a random one is in use."""
        return self._secret_key_generated


def log_configuration_warnings(settings: Settings) -> None:
    """Log settings that are acceptable locally but unsafe for a shared deployment.

    Called once logging is configured, so the warnings use the chosen format.
    """
    if settings.secret_key_generated:
        logger.warning(
            "WATCHPOST_SECRET_KEY is not set; using a random key. "
            "Sessions will not survive a restart."
        )


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings instance (cached after first use)."""
    return Settings()
