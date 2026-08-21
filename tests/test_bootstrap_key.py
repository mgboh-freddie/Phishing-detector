"""Tests for seeding an API key from BOOTSTRAP_API_KEY at startup.

Render's free plan has no shell (so `python -m api.keys create` has
nowhere to run) and wipes the filesystem on every restart (so a key
created any other way would vanish). Seeding from an environment
variable solves both: the key lives in the platform's env config.

These tests build the app themselves rather than using the `client`
fixture from conftest.py, because BOOTSTRAP_API_KEY must be set before
the app (and its lifespan) runs.
"""

import pytest

from api import store
from api.config import get_settings

BOOTSTRAP_KEY = "a-strong-bootstrap-key-value-123"


@pytest.fixture
def build_app(tmp_path, monkeypatch):
    """Returns a factory that sets env vars and builds a fresh app.

    Callers control exactly when the app (and its lifespan) is
    constructed, since BOOTSTRAP_API_KEY has to be in the environment
    before that happens.
    """
    monkeypatch.setenv("DB_PATH", str(tmp_path / "api.db"))
    monkeypatch.setenv("DASHBOARD_PASSWORD", "test-password")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("DEBUG", "true")

    def factory(**env):
        for key, value in env.items():
            monkeypatch.setenv(key, value)
        get_settings.cache_clear()

        from fastapi.testclient import TestClient

        from api.main import create_app

        return TestClient(create_app())

    yield factory
    get_settings.cache_clear()


def test_bootstrap_key_authenticates_against_a_real_endpoint(build_app):
    app = build_app(BOOTSTRAP_API_KEY=BOOTSTRAP_KEY)

    with app as client:
        response = client.get(
            "/v1/scans", headers={"Authorization": f"Bearer {BOOTSTRAP_KEY}"}
        )

    assert response.status_code == 200


def test_starting_twice_with_the_same_key_creates_exactly_one_row(build_app):
    db_path = get_settings().db_path

    with build_app(BOOTSTRAP_API_KEY=BOOTSTRAP_KEY):
        pass
    with build_app(BOOTSTRAP_API_KEY=BOOTSTRAP_KEY):
        pass

    with store.connect(db_path) as conn:
        count = conn.execute(
            "SELECT COUNT(*) AS n FROM api_keys WHERE key_hash = ?",
            (store.hash_key(BOOTSTRAP_KEY),),
        ).fetchone()["n"]

    assert count == 1


def test_revoked_bootstrap_key_stays_revoked_across_a_restart(build_app):
    with build_app(BOOTSTRAP_API_KEY=BOOTSTRAP_KEY):
        pass

    db_path = get_settings().db_path
    row = store.find_key_by_hash(db_path, store.hash_key(BOOTSTRAP_KEY))
    assert store.revoke_key(db_path, row["id"]) is True

    app = build_app(BOOTSTRAP_API_KEY=BOOTSTRAP_KEY)
    with app as client:
        response = client.get(
            "/v1/scans", headers={"Authorization": f"Bearer {BOOTSTRAP_KEY}"}
        )

    assert response.status_code == 401

    row_after = store.find_key_by_hash(db_path, store.hash_key(BOOTSTRAP_KEY))
    assert row_after["revoked_at"] is not None

    with store.connect(db_path) as conn:
        count = conn.execute(
            "SELECT COUNT(*) AS n FROM api_keys WHERE key_hash = ?",
            (store.hash_key(BOOTSTRAP_KEY),),
        ).fetchone()["n"]
    assert count == 1


def test_a_short_bootstrap_key_raises_runtime_error_at_startup(build_app):
    app = build_app(BOOTSTRAP_API_KEY="too-short")

    with pytest.raises(RuntimeError, match="BOOTSTRAP_API_KEY"):
        with app:
            pass


def test_unset_bootstrap_key_creates_nothing_and_behaves_as_before(build_app):
    with build_app():
        pass

    db_path = get_settings().db_path
    with store.connect(db_path) as conn:
        rows = conn.execute("SELECT id FROM api_keys").fetchall()

    assert [r["id"] for r in rows] == [store.INTERNAL_KEY_ID]


def test_seeded_key_name_comes_from_bootstrap_api_key_name(build_app):
    with build_app(BOOTSTRAP_API_KEY=BOOTSTRAP_KEY, BOOTSTRAP_API_KEY_NAME="ops-friend"):
        pass

    db_path = get_settings().db_path
    row = store.find_key_by_hash(db_path, store.hash_key(BOOTSTRAP_KEY))
    assert row["name"] == "ops-friend"
