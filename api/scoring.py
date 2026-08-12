"""Model loading and prediction.

The feature-order guard here is the important part. If the extractor's
FEATURE_ORDER ever drifts from the order the model was trained on,
predictions become meaningless without anything raising an error.
Refusing to start is the only safe response.
"""

import hashlib
import os
from dataclasses import dataclass
from typing import Any

import joblib
import pandas as pd

from extract_features import FEATURE_ORDER, extract_features


@dataclass(frozen=True)
class Bundle:
    model: Any
    threshold: float
    features: list
    version: str


def _file_version(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()[:12]


def load_bundle(path: str) -> Bundle:
    if not os.path.exists(path):
        raise RuntimeError(
            f"Model not found at {path}. Set MODEL_PATH to the bundle location."
        )

    raw = joblib.load(path)
    features = list(raw["features"])

    if features != list(FEATURE_ORDER):
        raise RuntimeError(
            "Feature mismatch between extractor and model.\n"
            f"  model expects:   {features}\n"
            f"  extractor gives: {list(FEATURE_ORDER)}\n"
            "Predictions would be meaningless. Refusing to start."
        )

    # The bundle carries no version key, so identify it by content hash.
    version = raw.get("version") or _file_version(path)

    return Bundle(
        model=raw["model"],
        threshold=float(raw["threshold"]),
        features=features,
        version=version,
    )


def score_html(bundle: Bundle, html: str, page_url: str = None):
    """Return (phishing_probability, features) for a page."""
    features = extract_features(html, page_url=page_url)
    X = pd.DataFrame([features])[bundle.features]
    score = float(bundle.model.predict_proba(X)[:, 1][0])
    return score, features


def verdict_for(score: float, threshold: float) -> str:
    return "phishing" if score >= threshold else "benign"


def build_warnings(features: dict, verdict: str, tag_threshold: int) -> list:
    """Surface known model limitations at the point of use.

    The model was trained on benign pages with a median 514 tags and
    malicious pages with 91, so it has partly learned "small and simple
    means phishing". Small business sites are both our intended customer
    and our blind spot, so a flag on a small page gets an explicit caveat.
    """
    warnings = []

    if verdict == "phishing" and features.get("tag_count", 0) < tag_threshold:
        warnings.append("small_simple_site")

    if features.get("min_link_length", 0) == 0:
        warnings.append("no_links_found")

    return warnings
