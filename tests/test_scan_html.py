from tests.conftest import read_fixture


def test_scan_html_returns_a_full_verdict(client):
    response = client.post(
        "/v1/scan",
        json={"html": read_fixture("phishy.html")},
        headers=client.auth_headers,
    )

    assert response.status_code == 200
    body = response.json()

    assert body["id"].startswith("scn_")
    assert body["source"] == "html"
    assert 0.0 <= body["score"] <= 1.0
    assert body["verdict"] in ("phishing", "benign")
    assert body["threshold"] == 0.30
    assert len(body["features"]) == 13
    assert body["tls_verified"] is None
    assert body["elapsed_ms"] >= 0
    assert body["created_at"].endswith("Z")


def test_features_are_always_returned(client):
    """A bare score is not auditable. A practitioner needs the evidence."""
    from extract_features import FEATURE_ORDER

    response = client.post(
        "/v1/scan",
        json={"html": "<html><body><form></form></body></html>"},
        headers=client.auth_headers,
    )

    assert set(response.json()["features"]) == set(FEATURE_ORDER)


def test_bakery_page_is_flagged_with_the_bias_warning(client):
    response = client.post(
        "/v1/scan",
        json={"html": read_fixture("realistic_benign.html")},
        headers=client.auth_headers,
    )
    body = response.json()

    assert body["verdict"] == "phishing"
    assert "small_simple_site" in body["warnings"]


def test_raising_the_threshold_changes_the_verdict(client):
    html = read_fixture("realistic_benign.html")

    low = client.post(
        "/v1/scan", json={"html": html, "threshold": 0.30}, headers=client.auth_headers
    ).json()
    high = client.post(
        "/v1/scan", json={"html": html, "threshold": 0.95}, headers=client.auth_headers
    ).json()

    assert low["verdict"] == "phishing"
    assert high["verdict"] == "benign"
    assert high["threshold"] == 0.95


def test_page_url_alongside_html_does_not_fetch(client):
    """Supplying both is valid: the URL only classifies links."""
    response = client.post(
        "/v1/scan",
        json={
            "html": '<html><a href="https://example.com/x">y</a></html>',
            "url": "https://example.com/",
        },
        headers=client.auth_headers,
    )

    body = response.json()
    assert body["source"] == "html"
    assert body["features"]["internal_link_count"] == 1


def test_neither_url_nor_html_is_a_422(client):
    response = client.post("/v1/scan", json={}, headers=client.auth_headers)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_threshold_out_of_range_is_a_422(client):
    response = client.post(
        "/v1/scan",
        json={"html": "<html></html>", "threshold": 1.5},
        headers=client.auth_headers,
    )
    assert response.status_code == 422


def test_oversized_html_is_a_413(client):
    response = client.post(
        "/v1/scan",
        json={"html": "x" * (5 * 1024 * 1024 + 1)},
        headers=client.auth_headers,
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "payload_too_large"


def test_missing_key_is_a_401(client):
    response = client.post("/v1/scan", json={"html": "<html></html>"})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"


def test_bad_key_is_a_401(client):
    response = client.post(
        "/v1/scan",
        json={"html": "<html></html>"},
        headers={"Authorization": "Bearer sk_live_wrong"},
    )
    assert response.status_code == 401


def test_rate_limit_returns_429_with_retry_after(client):
    from api import store
    from api.config import get_settings

    key_id, plaintext = store.create_key(
        get_settings().db_path, "tiny", rate_limit=2
    )
    headers = {"Authorization": f"Bearer {plaintext}"}

    for _ in range(2):
        assert client.post(
            "/v1/scan", json={"html": "<html></html>"}, headers=headers
        ).status_code == 200

    response = client.post(
        "/v1/scan", json={"html": "<html></html>"}, headers=headers
    )
    assert response.status_code == 429
    assert response.json()["error"]["code"] == "rate_limited"
    assert int(response.headers["Retry-After"]) > 0
