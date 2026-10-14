"""Session tokens: signed JWTs that name a user and their session version.

A token carries the user ID (``sub``), the user's session version (``sv``),
a CSRF secret (``csrf``) and the usual timestamps. It is signed with
HS256 using ``WATCHPOST_SECRET_KEY``. The browser receives it in an
HttpOnly cookie, so page scripts cannot read it; the CSRF secret goes in
a separate readable cookie and must be echoed in the ``X-CSRF-Token``
header of every state-changing request made with that cookie.

Raising a user's session version (password change, "sign out everywhere",
deactivation) invalidates every token issued before.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt

from watchpost.core.config import Settings
from watchpost.db.models import User

ALGORITHM = "HS256"
ISSUER = "watchpost"
SESSION_COOKIE = "watchpost_session"
CSRF_COOKIE = "watchpost_csrf"
CSRF_HEADER = "X-CSRF-Token"
_LEEWAY = timedelta(seconds=30)


class InvalidSessionError(Exception):
    """The token is malformed, forged, expired or otherwise unusable."""


@dataclass(frozen=True, slots=True)
class Session:
    token: str
    csrf: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class SessionClaims:
    user_id: int
    session_version: int
    csrf: str
    expires_at: datetime


def _key(settings: Settings) -> str:
    if settings.secret_key is None:  # pragma: no cover - settings always provide one
        msg = "no secret key configured"
        raise RuntimeError(msg)
    return settings.secret_key.get_secret_value()


def issue_session(user: User, settings: Settings, now: datetime | None = None) -> Session:
    """A new signed token for ``user``, valid for ``settings.session_hours``."""
    issued = now or datetime.now(UTC)
    expires = issued + timedelta(hours=settings.session_hours)
    csrf = secrets.token_urlsafe(32)
    payload = {
        "iss": ISSUER,
        "sub": str(user.id),
        "sv": user.session_version,
        "csrf": csrf,
        "iat": issued,
        "exp": expires,
        "jti": secrets.token_urlsafe(12),
    }
    return Session(jwt.encode(payload, _key(settings), algorithm=ALGORITHM), csrf, expires)


def read_session(token: str, settings: Settings) -> SessionClaims:
    """The claims of a valid token.

    Raises:
        InvalidSessionError: for anything but a well-formed, correctly signed,
            unexpired token issued by this platform.
    """
    try:
        payload = jwt.decode(
            token,
            _key(settings),
            algorithms=[ALGORITHM],
            issuer=ISSUER,
            leeway=_LEEWAY,
            options={"require": ["exp", "iat", "sub", "iss"]},
        )
        return SessionClaims(
            user_id=int(payload["sub"]),
            session_version=int(payload["sv"]),
            csrf=str(payload["csrf"]),
            expires_at=datetime.fromtimestamp(int(payload["exp"]), tz=UTC),
        )
    except (jwt.PyJWTError, KeyError, TypeError, ValueError) as exc:
        msg = "invalid or expired session"
        raise InvalidSessionError(msg) from exc
