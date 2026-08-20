"""The scan pipeline, shared by the JSON API and the dashboard.

Both front doors call run_scan, so they cannot give different answers to
the same page.
"""

import hashlib
import time

from api import scoring, store
from api.fetching import fetch


def resolve_threshold(requested, key_row, settings) -> float:
    """Request, then key default, then global default."""
    if requested is not None:
        return float(requested)
    if key_row is not None and key_row["threshold"] is not None:
        return float(key_row["threshold"])
    return float(settings.default_threshold)


def run_scan(
    bundle,
    settings,
    key_id: str,
    threshold_default,
    *,
    html=None,
    url=None,
    source: str,
    target: str,
    requested_threshold=None,
):
    """Score a page, persist the result, return the response dict."""
    started = time.perf_counter()

    tls_verified = None
    truncated = False
    page_url = url

    if html is None:
        result = fetch(url, settings)
        html = result.html
        page_url = result.final_url
        target = result.final_url
        tls_verified = result.tls_verified
        truncated = result.truncated

    score, features = scoring.score_html(bundle, html, page_url=page_url)

    threshold = (
        float(requested_threshold)
        if requested_threshold is not None
        else float(threshold_default)
    )
    verdict = scoring.verdict_for(score, threshold)
    warnings = scoring.build_warnings(
        features, verdict, settings.small_site_tag_threshold
    )

    if tls_verified is False:
        warnings.append("tls_verification_failed")
    if truncated:
        warnings.append("truncated")

    record = {
        "id": store.new_id("scn"),
        "key_id": key_id,
        "source": source,
        "target": target,
        "content_sha256": hashlib.sha256(html.encode("utf-8", "replace")).hexdigest(),
        "score": round(score, 4),
        "verdict": verdict,
        "threshold": threshold,
        "features": features,
        "warnings": warnings,
        "tls_verified": tls_verified,
        "model_version": bundle.version,
        "elapsed_ms": int((time.perf_counter() - started) * 1000),
        "created_at": store.utcnow(),
        "raw_html": html,
    }

    store.save_scan(settings.db_path, record, store_raw_html=settings.store_raw_html)

    response = dict(record)
    response.pop("raw_html")
    response.pop("key_id")
    response.pop("content_sha256")
    return response
