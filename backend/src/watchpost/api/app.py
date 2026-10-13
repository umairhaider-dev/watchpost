"""FastAPI application factory.

Run with ``uvicorn watchpost.api.app:create_app --factory``.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from arq.connections import ArqRedis
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from watchpost import __version__
from watchpost.api.deps import AppResources
from watchpost.api.middleware import RequestSizeLimitMiddleware
from watchpost.api.routes import api_router
from watchpost.api.routes.ingest import UPLOAD_PATH
from watchpost.core.config import Settings, get_settings, log_configuration_warnings
from watchpost.core.logging import configure_logging
from watchpost.db.session import create_engine, create_session_factory
from watchpost.worker.queue import ArqJobQueue

logger = logging.getLogger(__name__)

DEFAULT_MAX_BODY_BYTES = 1024 * 1024
MULTIPART_OVERHEAD_BYTES = 64 * 1024


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Create the database engine and Redis client, and close them on shutdown."""
    settings: Settings = app.state.settings
    engine = create_engine(settings)
    # Connections are opened lazily, so the API can start (and report itself
    # as not ready) even if Redis is briefly unavailable.
    redis = ArqRedis.from_url(str(settings.redis_url))
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    app.state.resources = AppResources(
        engine=engine,
        session_factory=create_session_factory(engine),
        redis=redis,
        queue=ArqJobQueue(redis),
    )
    logger.info("Watchpost API %s started (env=%s)", __version__, settings.env.value)
    try:
        yield
    finally:
        await redis.aclose()
        await engine.dispose()
        logger.info("Watchpost API stopped")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the FastAPI application."""
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_format)
    log_configuration_warnings(settings)

    app = FastAPI(
        title="Watchpost",
        summary="SOC investigation and threat detection platform",
        version=__version__,
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.settings = settings

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )
    app.add_middleware(
        RequestSizeLimitMiddleware,
        default_max_bytes=DEFAULT_MAX_BODY_BYTES,
        # Room for the multipart envelope around the file itself.
        path_limits=[(UPLOAD_PATH, settings.max_upload_bytes + MULTIPART_OVERHEAD_BYTES)],
    )
    app.include_router(api_router, prefix="/api")
    return app
