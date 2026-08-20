"""GET /v1/scans and GET /v1/scans/{id}"""

from fastapi import APIRouter, Depends, Query

from api import store
from api.auth import require_key
from api.config import Settings, get_settings
from api.errors import ApiError
from api.schemas import ScanListResponse

router = APIRouter(prefix="/v1", tags=["history"])


@router.get("/scans", response_model=ScanListResponse)
def list_scans(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    key_row=Depends(require_key),
    settings: Settings = Depends(get_settings),
):
    return {
        "total": store.count_scans(settings.db_path, key_row["id"]),
        "limit": limit,
        "offset": offset,
        "scans": store.list_scans(settings.db_path, key_row["id"], limit, offset),
    }


@router.get("/scans/{scan_id}")
def get_scan(
    scan_id: str,
    key_row=Depends(require_key),
    settings: Settings = Depends(get_settings),
):
    record = store.get_scan(settings.db_path, key_row["id"], scan_id)
    if record is None:
        raise ApiError("No such scan.", "not_found", 404)
    return record
