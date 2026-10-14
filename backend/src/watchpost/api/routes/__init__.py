"""API route modules, collected into a single router."""

from fastapi import APIRouter

from watchpost.api.routes import (
    alerts,
    detection,
    events,
    health,
    ingest,
    intel,
    meta,
    rules,
    users,
)

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(meta.router)
api_router.include_router(ingest.router)
api_router.include_router(events.router)
api_router.include_router(rules.router)
api_router.include_router(detection.router)
api_router.include_router(alerts.router)
api_router.include_router(intel.router)
api_router.include_router(users.router)

__all__ = ["api_router"]
