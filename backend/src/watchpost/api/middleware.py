"""ASGI middleware."""

from __future__ import annotations

from collections.abc import Sequence

from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class _BodyTooLargeError(Exception):
    pass


class RequestSizeLimitMiddleware:
    """Reject request bodies over a size limit with ``413``.

    FastAPI reads and spools a multipart body before the endpoint runs, so
    the limit has to be enforced here. Requests that declare a
    ``Content-Length`` over the limit are refused without reading the body;
    chunked uploads are cut off as soon as they cross it.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        default_max_bytes: int,
        path_limits: Sequence[tuple[str, int]] = (),
    ) -> None:
        self.app = app
        self.default_max_bytes = default_max_bytes
        self.path_limits = tuple(path_limits)

    def limit_for(self, path: str) -> int:
        for prefix, limit in self.path_limits:
            if path.startswith(prefix):
                return limit
        return self.default_max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self.limit_for(scope["path"])
        declared = Headers(scope=scope).get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > limit:
            await self._reject(limit, scope, receive, send)
            return

        received = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise _BodyTooLargeError
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _BodyTooLargeError:
            if response_started:
                raise
            await self._reject(limit, scope, receive, send)

    @staticmethod
    async def _reject(limit: int, scope: Scope, receive: Receive, send: Send) -> None:
        response = JSONResponse(
            {"detail": f"request body is larger than the {limit // (1024 * 1024)} MiB limit"},
            status_code=413,
        )
        await response(scope, receive, send)
