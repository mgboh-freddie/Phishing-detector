import pytest

from api.scoring import (
    Bundle,
    build_warnings,
    load_bundle,
    score_html,
    verdict_for,
)

BENIGN_FIXTURE = "data/realistic_benign.html"
PHISHY_FIXTURE = "data/phishy.html"


@pytest.fixture(scope="module")
def bundle():
    return load_bundle("phishing_html_model.joblib")


def read(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def test_bundle_exposes_threshold_and_version(bundle):
    assert bundle.threshold == 0.30
    assert len(bundle.features) == 13
    assert len(bundle.version) > 0


def test_missing_model_file_raises():
    with pytest.raises(RuntimeError, match="Model not found"):
        load_bundle("no_such_model.joblib")


def test_feature_mismatch_raises(bundle, monkeypatch, tmp_path):
    import joblib

    bad = {
        "model": bundle.model,
        "threshold": 0.3,
        "features": ["wrong_feature"],
    }
    path = tmp_path / "bad.joblib"
    joblib.dump(bad, path)

    with pytest.raises(RuntimeError, match="Feature mismatch"):
        load_bundle(str(path))


def test_phishy_fixture_scores_higher_than_benign(bundle):
    phishy, _ = score_html(bundle, read(PHISHY_FIXTURE))
    benign, _ = score_html(bundle, read(BENIGN_FIXTURE))
    assert phishy > benign


def test_score_returns_all_thirteen_features(bundle):
    from extract_features import FEATURE_ORDER

    _, features = score_html(bundle, read(PHISHY_FIXTURE))
    assert set(features) == set(FEATURE_ORDER)


def test_scoring_matches_scan_py_exactly(bundle):
    """Success criterion 3: the API must not change the product's answers."""
    import pandas as pd

    from extract_features import extract_from_file

    expected_features = extract_from_file(PHISHY_FIXTURE)
    X = pd.DataFrame([expected_features])[bundle.features]
    expected_score = float(bundle.model.predict_proba(X)[:, 1][0])

    actual_score, actual_features = score_html(bundle, read(PHISHY_FIXTURE))

    assert actual_score == expected_score
    assert actual_features == expected_features


def test_page_url_changes_link_classification(bundle):
    html = '<html><body><a href="https://example.com/a">x</a></body></html>'
    _, without = score_html(bundle, html)
    _, with_url = score_html(bundle, html, page_url="https://example.com/")

    assert without["external_link_count"] == 1
    assert with_url["internal_link_count"] == 1


def test_verdict_uses_threshold_inclusively():
    assert verdict_for(0.30, 0.30) == "phishing"
    assert verdict_for(0.2999, 0.30) == "benign"


def test_small_simple_site_warning_fires_on_the_bakery_page(bundle):
    """The documented bias must be visible, not hidden."""
    score, features = score_html(bundle, read(BENIGN_FIXTURE))
    v = verdict_for(score, 0.30)
    warnings = build_warnings(features, v, tag_threshold=400)

    assert v == "phishing"
    assert "small_simple_site" in warnings


def test_no_warning_when_verdict_is_benign():
    features = {"tag_count": 10, "min_link_length": 5}
    assert build_warnings(features, "benign", tag_threshold=400) == []


def test_no_links_found_warning():
    features = {"tag_count": 900, "min_link_length": 0}
    assert "no_links_found" in build_warnings(features, "benign", tag_threshold=400)
