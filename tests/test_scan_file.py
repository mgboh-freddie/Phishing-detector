def test_upload_an_html_file(client):
    with open("data/phishy.html", "rb") as fh:
        response = client.post(
            "/v1/scan/file",
            files={"file": ("phishy.html", fh, "text/html")},
            headers=client.auth_headers,
        )

    assert response.status_code == 200
    body = response.json()
    assert body["source"] == "file"
    assert body["target"] == "phishy.html"
    assert len(body["features"]) == 13


def test_non_html_extension_is_rejected(client):
    response = client.post(
        "/v1/scan/file",
        files={"file": ("payload.exe", b"MZ\x90\x00", "application/octet-stream")},
        headers=client.auth_headers,
    )

    assert response.status_code == 415
    assert response.json()["error"]["code"] == "unsupported_content_type"


def test_oversized_upload_is_a_413(client):
    big = b"<html>" + b"x" * (5 * 1024 * 1024) + b"</html>"
    response = client.post(
        "/v1/scan/file",
        files={"file": ("big.html", big, "text/html")},
        headers=client.auth_headers,
    )

    assert response.status_code == 413


def test_upload_requires_a_key(client):
    response = client.post(
        "/v1/scan/file", files={"file": ("x.html", b"<html></html>", "text/html")}
    )
    assert response.status_code == 401
