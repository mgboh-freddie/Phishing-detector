"""POST /v1/scan"""

from fastapi import APIRouter, Depends, File, Request, UploadFile

from api.auth import require_key
from api.config import Settings, get_settings
from api.schemas import MAX_HTML_BYTES, ScanRequest, ScanResponse
from api.service import resolve_threshold, run_scan
from api.errors import ApiError

router = APIRouter(prefix="/v1", tags=["scan"])


@router.post("/scan", response_model=ScanResponse)
def scan(
    body: ScanRequest,
    request: Request,
    key_row=Depends(require_key),
    settings: Settings = Depends(get_settings),
):
    if body.html is not None and len(body.html.encode("utf-8")) > MAX_HTML_BYTES:
        raise ApiError("HTML body exceeds 5 MB.", "payload_too_large", 413)

    source = "html" if body.html is not None else "url"
    target = body.url if body.url else "(pasted html)"

    return run_scan(
        request.app.state.bundle,
        settings,
        key_id=key_row["id"],
        threshold_default=resolve_threshold(None, key_row, settings),
        html=body.html,
        url=body.url,
        source=source,
        target=target,
        requested_threshold=body.threshold,
    )


ALLOWED_UPLOAD_SUFFIXES = (".html", ".htm")


@router.post("/scan/file", response_model=ScanResponse)
async def scan_file(
    request: Request,
    file: UploadFile = File(...),
    threshold: float = None,
    key_row=Depends(require_key),
    settings: Settings = Depends(get_settings),
):
    name = (file.filename or "upload").strip()

    if not name.lower().endswith(ALLOWED_UPLOAD_SUFFIXES):
        raise ApiError(
            "Only .html and .htm files can be scanned.",
            "unsupported_content_type",
            415,
        )

    raw = await file.read(MAX_HTML_BYTES + 1)
    if len(raw) > MAX_HTML_BYTES:
        raise ApiError("Uploaded file exceeds 5 MB.", "payload_too_large", 413)

    if threshold is not None and not 0.0 <= threshold <= 1.0:
        raise ApiError("threshold must be between 0 and 1.", "validation_error", 422)

    return run_scan(
        request.app.state.bundle,
        settings,
        key_id=key_row["id"],
        threshold_default=resolve_threshold(None, key_row, settings),
        html=raw.decode("utf-8", errors="replace"),
        url=None,
        source="file",
        target=name,
        requested_threshold=threshold,
    )
