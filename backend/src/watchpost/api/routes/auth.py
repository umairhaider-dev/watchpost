"""Signing in and out, and changing one's own password.

The browser signs in with ``POST /auth/login`` and receives two cookies:
an HttpOnly session cookie scoped to ``/api``, and a readable CSRF cookie
whose value the UI echoes in ``X-CSRF-Token``. Scripts use
``POST /auth/token`` and send ``Authorization: Bearer <token>`` instead.
Every attempt, successful or not, is written to the audit log.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, ConfigDict, Field

from watchpost import audit
from watchpost.api.deps import (
    ActorDep,
    SessionDep,
    SettingsDep,
    ThrottleDep,
    UserDep,
    client_address,
)
from watchpost.auth.service import authenticate, set_password
from watchpost.auth.throttle import LoginThrottle
from watchpost.auth.tokens import CSRF_COOKIE, SESSION_COOKIE, Session, issue_session
from watchpost.core.config import Settings
from watchpost.core.passwords import (
    MAX_PASSWORD_LENGTH,
    WeakPasswordError,
    check_password_policy,
    verify_password,
)
from watchpost.db.models import User, UserRole

router = APIRouter(prefix="/auth", tags=["auth"])

MAX_USERNAME = 64


class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=MAX_USERNAME)
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)


class Me(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    full_name: str | None
    email: str | None
    role: UserRole


class SignedIn(BaseModel):
    user: Me
    expires_at: datetime


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - the OAuth2 token type, not a secret
    expires_in: int


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)
    new_password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)


def _set_cookies(response: Response, session: Session, settings: Settings) -> None:
    max_age = settings.session_hours * 3600
    response.set_cookie(
        SESSION_COOKIE,
        session.token,
        max_age=max_age,
        path="/api",
        httponly=True,
        secure=settings.secure_cookies,
        samesite="strict",
    )
    response.set_cookie(
        CSRF_COOKIE,
        session.csrf,
        max_age=max_age,
        path="/",
        httponly=False,
        secure=settings.secure_cookies,
        samesite="strict",
    )


def _clear_cookies(response: Response, settings: Settings) -> None:
    for name, path, httponly in ((SESSION_COOKIE, "/api", True), (CSRF_COOKIE, "/", False)):
        response.delete_cookie(
            name, path=path, httponly=httponly, secure=settings.secure_cookies, samesite="strict"
        )


async def _sign_in(
    session: SessionDep,
    throttle: LoginThrottle,
    request: Request,
    username: str,
    password: str,
) -> User:
    """Check credentials, with throttling and an audit entry either way."""
    name = username.strip()[:MAX_USERNAME]
    address = client_address(request)
    wait = await throttle.retry_after(name, address)
    if wait is not None:
        await audit.record(
            session,
            "auth.login_blocked",
            actor=None,
            target_type="user",
            target_id=name,
            username=name,
        )
        await session.commit()
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too many failed sign-ins; try again later",
            headers={"Retry-After": str(wait)},
        )
    user = await authenticate(session, name, password)
    if user is None:
        await throttle.failed(name, address)
        await audit.record(
            session,
            "auth.login_failed",
            actor=None,
            target_type="user",
            target_id=name,
            username=name,
        )
        await session.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "wrong user name or password")
    await throttle.succeeded(name)
    await audit.record(session, "auth.login", actor=user, target_type="user", target_id=user.id)
    await session.commit()
    return user


@router.post(
    "/login",
    response_model=SignedIn,
    responses={
        401: {"description": "Wrong user name or password"},
        429: {"description": "Too many failed attempts"},
    },
)
async def login(
    body: Credentials,
    request: Request,
    response: Response,
    session: SessionDep,
    settings: SettingsDep,
    throttle: ThrottleDep,
) -> SignedIn:
    """Sign in from the browser; sets the session and CSRF cookies."""
    user = await _sign_in(session, throttle, request, body.username, body.password)
    issued = issue_session(user, settings)
    _set_cookies(response, issued, settings)
    return SignedIn(user=Me.model_validate(user), expires_at=issued.expires_at)


@router.post("/token", response_model=TokenOut)
async def token(
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    throttle: ThrottleDep,
) -> TokenOut:
    """Get a bearer token for scripts and the API docs (OAuth2 password flow)."""
    user = await _sign_in(session, throttle, request, form.username, form.password)
    issued = issue_session(user, settings)
    return TokenOut(access_token=issued.token, expires_in=settings.session_hours * 3600)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    response: Response,
    session: SessionDep,
    settings: SettingsDep,
    user: ActorDep,
    everywhere: bool = False,
) -> None:
    """Sign out; ``everywhere=true`` also ends every other session of this user."""
    if user is not None:
        if everywhere:
            user.session_version += 1
        await audit.record(
            session,
            "auth.logout",
            actor=user,
            target_type="user",
            target_id=user.id,
            details={"everywhere": everywhere},
        )
        await session.commit()
    _clear_cookies(response, settings)


@router.get("/me", response_model=Me)
async def me(user: UserDep) -> User:
    """The signed-in user."""
    return user


@router.post(
    "/password",
    response_model=SignedIn,
    responses={400: {"description": "The current password is wrong or the new one is too weak"}},
)
async def change_password(
    body: PasswordChange,
    response: Response,
    session: SessionDep,
    settings: SettingsDep,
    user: UserDep,
) -> SignedIn:
    """Change your own password. Other sessions are signed out; this one continues."""
    if not verify_password(user.password_hash, body.current_password):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "the current password is wrong")
    try:
        check_password_policy(body.new_password)
    except WeakPasswordError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    await set_password(session, user, body.new_password)
    await audit.record(
        session, "auth.password_changed", actor=user, target_type="user", target_id=user.id
    )
    await session.commit()
    issued = issue_session(user, settings)
    _set_cookies(response, issued, settings)
    return SignedIn(user=Me.model_validate(user), expires_at=issued.expires_at)
