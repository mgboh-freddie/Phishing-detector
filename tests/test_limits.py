"""MaxBodySizeMiddleware: the size cap must fire before auth and routing."""


def test_oversized_content_length_is_rejected_before_auth(client):
    """No Authorization header is sent. If the guard ran after auth this
    would come back 401; it must come back 413 instead, proving the size
    check happens ahead of Depends(require_key)."""
    response = client.post(
        "/v1/scan/file",
        files={"file": ("small.html", b"<html></html>", "text/html")},
        headers={"content-length": "999999999"},
    )

    assert response.status_code == 413
    body = response.json()
    assert body["error"]["code"] == "payload_too_large"


def test_malformed_content_length_does_not_crash(client):
    response = client.post(
        "/v1/scan/file",
        files={"file": ("small.html", b"<html></html>", "text/html")},
        headers={"content-length": "not-a-number", **client.auth_headers},
    )

    assert response.status_code == 200
