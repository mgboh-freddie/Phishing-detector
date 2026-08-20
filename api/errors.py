"""One error shape for the whole API."""

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from api.auth import AuthError
from api.fetching import FetchError


class ApiError(Exception):
    def __init__(self, message: str, code: str, status: int):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status


def _body(code: str, message: str):
    return {"error": {"code": code, "message": message}}


def register_error_handlers(app):
    @app.exception_handler(ApiError)
    def handle_api_error(request: Request, exc: ApiError):
        return JSONResponse(
            status_code=exc.status, content=_body(exc.code, exc.message)
        )

    @app.exception_handler(AuthError)
    def handle_auth_error(request: Request, exc: AuthError):
        headers = {"Retry-After": str(exc.retry_after)} if exc.retry_after else None
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
