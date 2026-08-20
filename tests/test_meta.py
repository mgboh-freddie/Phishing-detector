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


def test_corrupt_metrics_file_does_not_break_the_endpoint(client, tmp_path, monkeypatch):
    """model_metrics.json is supporting detail. The threshold, features,
    licence, and known limitations come from the bundle, so a corrupt
    metrics file must degrade to empty metrics rather than a 500."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "model_metrics.json").write_text("{ this is not json", encoding="utf-8")

    response = client.get("/v1/model", headers=client.auth_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["metrics"] == {}
    assert len(body["features"]) == 13
    assert "CC BY-NC" in body["licence"]


def test_missing_metrics_file_does_not_break_the_endpoint(client, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    response = client.get("/v1/model", headers=client.auth_headers)

    assert response.status_code == 200
    assert response.json()["metrics"] == {}
