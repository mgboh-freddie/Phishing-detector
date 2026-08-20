import os

import pytest


@pytest.fixture
def client(tmp_path, monkeypatch):
    """A TestClient with an isolated database and a known API key."""
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
        key_id, plaintext = store.create_key(
            get_settings().db_path, "test", threshold=0.30, rate_limit=60
        )
        test_client.key_id = key_id
        test_client.api_key = plaintext
        test_client.auth_headers = {"Authorization": f"Bearer {plaintext}"}
        yield test_client

    get_settings.cache_clear()


def read_fixture(name):
    with open(f"data/{name}", "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()
