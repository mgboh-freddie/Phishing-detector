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


def test_settings_repr_hides_every_secret(monkeypatch):
    """Settings shows up in traceback frames and the catch-all error handler
    logs tracebacks, so one unhandled exception would otherwise write every
    secret into the log."""
    from api.config import get_settings

    monkeypatch.setenv("DASHBOARD_PASSWORD", "PW-THAT-MUST-NOT-LEAK")
    monkeypatch.setenv("SECRET_KEY", "SIGNING-KEY-THAT-MUST-NOT-LEAK")
    monkeypatch.setenv("BOOTSTRAP_API_KEY", "sk_live_" + "B" * 32)
    get_settings.cache_clear()

    settings = get_settings()
    rendered = repr(settings)

    assert "PW-THAT-MUST-NOT-LEAK" not in rendered
    assert "SIGNING-KEY-THAT-MUST-NOT-LEAK" not in rendered
    assert "sk_live_" not in rendered
    # The values are still usable by code that legitimately needs them.
    assert settings.dashboard_password == "PW-THAT-MUST-NOT-LEAK"
    assert settings.bootstrap_api_key == "sk_live_" + "B" * 32
    get_settings.cache_clear()


def test_concurrent_seeding_creates_exactly_one_row(tmp_path):
    """Two instances starting at once must not both insert. key_hash is
    UNIQUE and the insert is INSERT OR IGNORE, so the loser no-ops rather
    than raising IntegrityError out of startup."""
    import threading

    from api import store

    db = str(tmp_path / "race.db")
    store.init_db(db)
    plaintext = "sk_live_" + "C" * 32

    results = []
    barrier = threading.Barrier(8)

    def seed():
        barrier.wait()
        results.append(store.ensure_bootstrap_key(db, plaintext, "racer", 0.30))

    threads = [threading.Thread(target=seed) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    with store.connect(db) as conn:
        rows = conn.execute(
            "SELECT COUNT(*) AS n FROM api_keys WHERE key_hash = ?",
            (store.hash_key(plaintext),),
        ).fetchone()["n"]

    assert rows == 1, "concurrent seeding created duplicate key rows"
    assert len([r for r in results if r is not None]) == 1, "more than one caller claimed to have created the key"
