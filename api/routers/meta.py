"""GET /v1/model and GET /v1/health"""

import json
import logging
import os

from fastapi import APIRouter, Depends, Request

from api.auth import require_key
from api.config import Settings, get_settings

router = APIRouter(prefix="/v1", tags=["meta"])

logger = logging.getLogger(__name__)

LICENCE = (
    "Model trained on CIC-Trap4Phish, CC BY-NC 4.0 — non-commercial use only. "
    "Cite Nejati et al. (2026), arXiv:2602.09015."
)

KNOWN_LIMITATIONS = [
    "Trained on benign pages with a median 514 HTML tags against malicious "
    "pages with 91, so small simple sites are over-flagged. Responses carry "
    "a small_simple_site warning when this applies."
]


@router.get("/health")
def health(request: Request):
    bundle = getattr(request.app.state, "bundle", None)
    return {
        "status": "ok",
        "model_loaded": bundle is not None,
        "model_version": bundle.version if bundle else None,
        "version": "1.0.0",
    }


@router.get("/model")
def model_info(
    request: Request,
    key_row=Depends(require_key),
    settings: Settings = Depends(get_settings),
):
    bundle = request.app.state.bundle

    # A missing or corrupt metrics file must not take the endpoint down.
    # It is supporting detail; the threshold, features, licence, and known
    # limitations below are the parts a caller actually needs, and they
    # come from the bundle rather than this file.
    metrics = {}
    if os.path.exists("model_metrics.json"):
        try:
            with open("model_metrics.json", "r", encoding="utf-8") as fh:
                metrics = json.load(fh)
        except (json.JSONDecodeError, OSError):
            logger.warning("model_metrics.json is unreadable; reporting no metrics.")

    return {
        "model_version": bundle.version,
        "threshold": bundle.threshold,
        "your_default_threshold": key_row["threshold"],
        "features": bundle.features,
        "metrics": metrics,
        "licence": LICENCE,
        "known_limitations": KNOWN_LIMITATIONS,
    }
