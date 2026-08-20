def scan_once(client, html="<html><body></body></html>"):
    return client.post(
        "/v1/scan", json={"html": html}, headers=client.auth_headers
    ).json()


def test_history_lists_newest_first(client):
    first = scan_once(client)
    second = scan_once(client)

    body = client.get("/v1/scans", headers=client.auth_headers).json()

    assert body["total"] == 2
    assert [s["id"] for s in body["scans"]] == [second["id"], first["id"]]


def test_history_paginates(client):
    for _ in range(3):
        scan_once(client)

    body = client.get("/v1/scans?limit=2&offset=0", headers=client.auth_headers).json()

    assert len(body["scans"]) == 2
    assert body["limit"] == 2
    assert body["offset"] == 0
    assert body["total"] == 3


def test_single_scan_includes_features(client):
    created = scan_once(client)

    body = client.get(f"/v1/scans/{created['id']}", headers=client.auth_headers).json()

    assert body["id"] == created["id"]
    assert len(body["features"]) == 13


def test_unknown_scan_is_a_404(client):
    response = client.get("/v1/scans/scn_nope", headers=client.auth_headers)
    assert response.status_code == 404


def test_another_keys_scan_is_not_visible(client):
    from api import store
    from api.config import get_settings

    created = scan_once(client)
    _, other = store.create_key(get_settings().db_path, "other")

    response = client.get(
        f"/v1/scans/{created['id']}", headers={"Authorization": f"Bearer {other}"}
    )
    assert response.status_code == 404


def test_history_requires_a_key(client):
    assert client.get("/v1/scans").status_code == 401
