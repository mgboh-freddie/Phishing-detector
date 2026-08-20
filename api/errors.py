"""One error shape for the whole API."""

import http
import logging

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from api.auth import AuthError
from api.fetching import FetchError

logger = logging.getLogger(__name__)


class ApiError(Exception):
    def __init__(self, message: str, code: str, status: int):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status


def _body(code: str, message: str):
    return {"error": {"code": code, "message": message}}


def _code_from_status(status_code: int) -> str:
    """snake_case code derived from the status phrase, e.g. 404 -> not_found."""
    try:
        phrase = http.HTTPStatus(status_code).phrase
    except ValueError:
        return "http_error"
    return phrase.lower().replace(" ", "_")


def register_error_handlers(app):
    @app.exception_handler(ApiError)
    def handle_api_error(request: Request, exc: ApiError):
        return JSONResponse(
            status_code=exc.status, content=_body(exc.code, exc.message)
        )

    @app.exception_handler(AuthError)
    def handle_auth_error(request: Request, exc: AuthError):
        headers = (
            {"Retry-After": str(exc.retry_after)}
            if exc.retry_after is not None
            else None
        )
        return JSONResponse(
            status_code=exc.status,
            content=_body(exc.code, exc.message),
            headers=headers,
        )

    @app.exception_handler(FetchError)
    def handle_fetch_error(request: Request, exc: FetchError):
        return JSONResponse(
            status_code=exc.status, content=_body(exc.code, str(exc))
        )

    @app.exception_handler(RequestValidationError)
    def handle_validation_error(request: Request, exc: RequestValidationError):
        first = exc.errors()[0] if exc.errors() else {}
        message = first.get("msg", "Request body failed validation.")
        return JSONResponse(
            status_code=422, content=_body("validation_error", message)
        )

    @app.exception_handler(StarletteHTTPException)
    def handle_http_exception(request: Request, exc: StarletteHTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content=_body(_code_from_status(exc.status_code), str(exc.detail)),
            headers=exc.headers,
        )

    @app.exception_handler(Exception)
    def handle_unhandled_exception(request: Request, exc: Exception):
        logger.exception(
            "Unhandled exception while processing %s %s",
            request.method,
            request.url.path,
        )
        return JSONResponse(
            status_code=500,
            content=_body("internal_error", "An internal error occurred."),
        )
