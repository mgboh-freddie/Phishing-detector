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


def _metrics_path(model_path: str) -> str:
    """A sibling `<model-stem>_metrics.json` next to the configured model,
    falling back to the historical `model_metrics.json` name so the
    current bundle keeps working unchanged."""
    stem, _ = os.path.splitext(model_path)
    derived = f"{stem}_metrics.json"
    if os.path.exists(derived):
        return derived
    return "model_metrics.json"


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
    metrics_path = _metrics_path(settings.model_path)
    metrics = {}
    if os.path.exists(metrics_path):
        try:
            with open(metrics_path, "r", encoding="utf-8") as fh:
                metrics = json.load(fh)
        except (json.JSONDecodeError, OSError):
            logger.warning("%s is unreadable; reporting no metrics.", metrics_path)

    return {
        "model_version": bundle.version,
        "threshold": bundle.threshold,
        "your_default_threshold": key_row["threshold"],
        "features": bundle.features,
        "metrics": metrics,
        "licence": bundle.licence or LICENCE,
        "known_limitations": bundle.known_limitations or KNOWN_LIMITATIONS,
    }
