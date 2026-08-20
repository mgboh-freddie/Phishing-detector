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


def test_model_metadata_prefers_the_bundles_own_licence_and_limitations(
    tmp_path, monkeypatch
):
    """A retrained, relicensed bundle must not still be reported as the
    non-commercial CC BY-NC model with the old bias description -- the
    whole point of MODEL_PATH being configuration is that this swap works."""
    import joblib

    raw = joblib.load("phishing_html_model.joblib")
    raw["licence"] = "MIT -- commercial use permitted."
    raw["known_limitations"] = ["Retrained; the small-site bias no longer applies."]
    bundle_path = tmp_path / "custom_model.joblib"
    joblib.dump(raw, bundle_path)

    monkeypatch.setenv("MODEL_PATH", str(bundle_path))
    monkeypatch.setenv("DB_PATH", str(tmp_path / "api.db"))
    monkeypatch.setenv("DASHBOARD_PASSWORD", "test-password")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("DEBUG", "true")

    from fastapi.testclient import TestClient

    from api import store
    from api.config import get_settings
    from api.main import create_app

    get_settings.cache_clear()
    app = create_app()
    with TestClient(app) as test_client:
        _, plaintext = store.create_key(
            get_settings().db_path, "test", threshold=0.30, rate_limit=60
        )
        response = test_client.get(
            "/v1/model", headers={"Authorization": f"Bearer {plaintext}"}
        )
    get_settings.cache_clear()

    assert response.status_code == 200
    body = response.json()
    assert body["licence"] == "MIT -- commercial use permitted."
    assert body["known_limitations"] == [
        "Retrained; the small-site bias no longer applies."
    ]
