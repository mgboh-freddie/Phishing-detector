"""The dashboard.

Calls run_scan directly rather than making HTTP requests back to this
same app — same code path as the JSON API, no self-call.
"""

import hmac

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from api import store
from api.config import Settings, get_settings
from api.fetching import FetchError
from api.routers.scan import ALLOWED_UPLOAD_SUFFIXES
from api.schemas import MAX_HTML_BYTES
from api.sessions import sign, verify
from api.service import run_scan

router = APIRouter(tags=["dashboard"])
templates = Jinja2Templates(directory="api/templates")

COOKIE_NAME = "session"
SESSION_VALUE = "signed-in"


def is_signed_in(request: Request, settings: Settings) -> bool:
    token = request.cookies.get(COOKIE_NAME)
    return bool(token) and verify(token, settings.secret_key) == SESSION_VALUE


def _redirect(target: str) -> RedirectResponse:
    return RedirectResponse(target, status_code=303)


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse(
        request, "login.html", {"signed_in": False, "error": None}
    )


@router.post("/login", response_class=HTMLResponse)
def login(
    request: Request,
    password: str = Form(...),
    settings: Settings = Depends(get_settings),
):
    if not hmac.compare_digest(
        password.encode("utf-8"), settings.dashboard_password.encode("utf-8")
    ):
        return templates.TemplateResponse(
            request,
            "login.html",
            {"signed_in": False, "error": "Incorrect password."},
            status_code=401,
        )

    response = _redirect("/")
    response.set_cookie(
        COOKIE_NAME,
        sign(SESSION_VALUE, settings.secret_key),
        httponly=True,
        samesite="lax",
        secure=not settings.debug,
    )
    return response


@router.post("/logout")
def logout():
    response = _redirect("/login")
    response.delete_cookie(COOKIE_NAME)
    return response


@router.get("/", response_class=HTMLResponse)
def scan_form(request: Request, settings: Settings = Depends(get_settings)):
    if not is_signed_in(request, settings):
        return _redirect("/login")
    return templates.TemplateResponse(
        request,
        "scan.html",
        {
            "signed_in": True,
            "result": None,
            "error": None,
            "default_threshold": settings.default_threshold,
        },
    )


@router.post("/", response_class=HTMLResponse)
async def submit_scan(
    request: Request,
    url: str = Form(default=""),
    html: str = Form(default=""),
    threshold: float = Form(default=None),
    file: UploadFile = File(default=None),
    settings: Settings = Depends(get_settings),
):
    if not is_signed_in(request, settings):
        return _redirect("/login")

    context = {
        "signed_in": True,
        "result": None,
        "error": None,
        "default_threshold": settings.default_threshold,
    }

    resolved_threshold = (
        threshold if threshold is not None else settings.default_threshold
    )
    if not 0.0 <= resolved_threshold <= 1.0:
        context["error"] = "Threshold must be between 0 and 1."
        return templates.TemplateResponse(request, "scan.html", context)

    uploaded = None
    if file is not None and file.filename:
        if not file.filename.lower().endswith(ALLOWED_UPLOAD_SUFFIXES):
            context["error"] = "Only .html and .htm files can be scanned."
            return templates.TemplateResponse(request, "scan.html", context)

        raw = await file.read(MAX_HTML_BYTES + 1)
        if len(raw) > MAX_HTML_BYTES:
            context["error"] = "That file is larger than 5 MB."
            return templates.TemplateResponse(request, "scan.html", context)
        uploaded = raw.decode("utf-8", errors="replace")

    if uploaded is not None:
        source, target, body = "file", file.filename, uploaded
    elif html.strip():
        source, target, body = "html", "(pasted html)", html
    elif url.strip():
        source, target, body = "url", url.strip(), None
    else:
        context["error"] = "Give a URL, some HTML, or a file."
        return templates.TemplateResponse(request, "scan.html", context)

    try:
        context["result"] = run_scan(
            request.app.state.bundle,
            settings,
            key_id=store.INTERNAL_KEY_ID,
            threshold_default=resolved_threshold,
            html=body,
            url=url.strip() or None,
            source=source,
            target=target,
            requested_threshold=resolved_threshold,
        )
    except FetchError as exc:
        context["error"] = str(exc)

    return templates.TemplateResponse(request, "scan.html", context)


@router.get("/history", response_class=HTMLResponse)
def history(request: Request, settings: Settings = Depends(get_settings)):
    if not is_signed_in(request, settings):
        return _redirect("/login")
    return templates.TemplateResponse(
        request,
        "history.html",
        {
            "signed_in": True,
            "scans": store.list_scans(settings.db_path, store.INTERNAL_KEY_ID, 100, 0),
        },
    )


@router.get("/scan/{scan_id}", response_class=HTMLResponse)
def scan_detail(
    scan_id: str, request: Request, settings: Settings = Depends(get_settings)
):
    if not is_signed_in(request, settings):
        return _redirect("/login")

    record = store.get_scan(settings.db_path, store.INTERNAL_KEY_ID, scan_id)
    return templates.TemplateResponse(
        request,
        "scan.html",
        {
            "signed_in": True,
            "result": record,
            "error": None if record else "No such scan.",
            "default_threshold": settings.default_threshold,
        },
    )
