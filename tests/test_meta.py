def test_health_needs_no_key(client):
    response = client.get("/v1/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["model_loaded"] is True


def test_model_metadata_reports_the_licence(client):
    response = client.get("/v1/model", headers=client.auth_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["threshold"] == 0.30
    assert len(body["features"]) == 13
    assert "CC BY-NC" in body["licence"]
    assert body["metrics"]["roc_auc"] == 0.9845


def test_model_metadata_requires_a_key(client):
    assert client.get("/v1/model").status_code == 401


def test_openapi_docs_are_served(client):
    assert client.get("/docs").status_code == 200
