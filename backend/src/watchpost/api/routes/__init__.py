"""API route modules, collected into a single router.

Health checks and sign-in are open; every other route needs a signed-in
user, and changing data needs at least an analyst (see
:func:`watchpost.api.deps.authorize`).
"""

from fastapi import APIRouter, Depends

from watchpost.api.deps import authorize, bind_request_context
from watchpost.api.routes import (
    alerts,
    audit,
    auth,
    cases,
    dashboard,
    detection,
    entities,
    events,
    health,
    ingest,
    intel,
    meta,
    mitre,
    rules,
    users,
)

PROTECTED = (
    meta,
    dashboard,
    ingest,
    events,
    rules,
    detection,
    alerts,
    cases,
    entities,
    mitre,
    intel,
    users,
    audit,
)

api_router = APIRouter(dependencies=[Depends(bind_request_context)])
api_router.include_router(health.router)
api_router.include_router(auth.router)
for module in PROTECTED:
    api_router.include_router(module.router, dependencies=[Depends(authorize)])

__all__ = ["api_router"]
