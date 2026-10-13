"""API route modules, collected into a single router."""

from fastapi import APIRouter

from watchpost.api.routes import events, health, ingest, meta

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(meta.router)
api_router.include_router(ingest.router)
api_router.include_router(events.router)

__all__ = ["api_router"]
