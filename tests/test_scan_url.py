import pytest

from tests.conftest import read_fixture


@pytest.fixture
def fake_fetch(monkeypatch):
    """Substitute the network. fetching.py has its own tests."""
    import api.service as service
    from api.fetching import FetchResult

    def _fetch(url, settings):
        return FetchResult(
            html=read_fixture("phishy.html"),
            final_url="https://phish.test/login-final",
            tls_verified=False,
            truncated=False,
        )

    monkeypatch.setattr(service, "fetch", _fetch)


def test_scan_url_reports_the_final_url_not_the_submitted_one(client, fake_fetch):
    response = client.post(
        "/v1/scan",
        json={"url": "https://phish.test/start"},
        headers=client.auth_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["source"] == "url"
    assert body["target"] == "https://phish.test/login-final"
    assert body["target"] != "https://phish.test/start"
    assert body["tls_verified"] is False
    assert "tls_verification_failed" in body["warnings"]


def test_blocked_url_is_a_403(client):
    response = client.post(
        "/v1/scan",
        json={"url": "http://169.254.169.254/latest/meta-data/"},
        headers=client.auth_headers,
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "url_blocked"


def test_non_http_scheme_is_a_400(client):
    response = client.post(
        "/v1/scan",
        json={"url": "file:///etc/passwd"},
        headers=client.auth_headers,
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_url"


def test_truncated_body_warns(client, monkeypatch):
    import api.service as service
    from api.fetching import FetchResult

    monkeypatch.setattr(
        service,
        "fetch",
        lambda url, settings: FetchResult(
            html="<html></html>",
            final_url="https://big.test/",
            tls_verified=True,
            truncated=True,
        ),
    )

    response = client.post(
        "/v1/scan", json={"url": "https://big.test/"}, headers=client.auth_headers
    )

    assert "truncated" in response.json()["warnings"]
