"""ASGI middleware enforcing the request size cap ahead of routing and auth.

FastAPI resolves the request body (and, for multipart uploads, spools it to
a SpooledTemporaryFile) before it resolves any `Depends(...)`, including
`Depends(require_key)`. That means an unauthenticated caller can push an
arbitrarily large body at an endpoint and have it fully received -- with
disk I/O for large multipart uploads -- before the handler ever runs, with
a 401 as the only consequence. An in-handler size check cannot prevent
that; it only bounds what the handler reads out of a body that has
already been received in full.

This middleware runs at the ASGI layer, wrapping routing (and therefore
dependency resolution) entirely, so it can reject an oversized request by
its Content-Length header before any body bytes are read and before
authentication happens.

Limitation, stated plainly: a chunked transfer-encoding request carries no
Content-Length header, so this middleware has no size to check in advance
and lets it through to routing. The in-handler size check in
api/routers/scan.py stays in place as defence in depth for that case.
Fully closing the chunked hole would require streaming enforcement (bound
the number of bytes read off the ASGI receive channel), which is out of
scope here.
"""

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from api.config import get_settings
from api.errors import _body


class MaxBodySizeMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        content_length = None
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                content_length = value
                break

        if content_length is not None:
            try:
                length = int(content_length)
            except ValueError:
                # Not a valid integer. Let the request through; the
                # handler's own checks (or the server) will deal with it.
                length = None

            if length is not None and length > get_settings().max_body_bytes:
                response = JSONResponse(
                    status_code=413,
                    content=_body(
                        "payload_too_large",
                        "Request body exceeds the maximum allowed size.",
                    ),
                )
                await response(scope, receive, send)
                return

        await self.app(scope, receive, send)
