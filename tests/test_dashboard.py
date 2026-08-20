import pytest

from api.sessions import sign, verify


def test_signed_token_round_trips():
    token = sign("logged-in", "secret")
    assert verify(token, "secret") == "logged-in"


def test_tampered_token_is_rejected():
    token = sign("logged-in", "secret")
    assert verify(token + "x", "secret") is None


def test_token_signed_with_another_secret_is_rejected():
    assert verify(sign("logged-in", "secret"), "other") is None


def test_root_redirects_to_login_when_signed_out(client):
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_history_redirects_to_login_when_signed_out(client):
    response = client.get("/history", follow_redirects=False)
    assert response.status_code == 303


def test_wrong_password_does_not_sign_in(client):
    response = client.post("/login", data={"password": "wrong"})
    assert response.status_code == 401
    assert "Incorrect password" in response.text


def test_correct_password_signs_in(client):
    response = client.post(
        "/login", data={"password": "test-password"}, follow_redirects=False
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/"


@pytest.fixture
def signed_in(client):
    client.post("/login", data={"password": "test-password"})
    return client


def test_scan_form_renders_when_signed_in(signed_in):
    response = signed_in.get("/")
    assert response.status_code == 200
    assert "Scan a page" in response.text


def test_pasted_html_is_scanned_and_shown(signed_in):
    with open("data/realistic_benign.html", encoding="utf-8") as fh:
        html = fh.read()

    response = signed_in.post("/", data={"html": html, "threshold": "0.30"})

    assert response.status_code == 200
    assert "phishing" in response.text.lower()
    # The bias warning must be a sentence, not a bare code.
    assert "small" in response.text.lower()


def test_dashboard_scan_appears_in_history(signed_in):
    signed_in.post("/", data={"html": "<html><body></body></html>"})

    response = signed_in.get("/history")

    assert response.status_code == 200
    assert "scn_" in response.text


def test_logout_clears_the_session(signed_in):
    signed_in.post("/logout")
    response = signed_in.get("/", follow_redirects=False)
    assert response.status_code == 303


def test_non_ascii_wrong_password_gives_401_not_500(client):
    response = client.post("/login", data={"password": "pässwort"})
    assert response.status_code == 401
    assert "Incorrect password" in response.text


def test_non_ascii_dashboard_password_can_log_in(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "api.db"))
    monkeypatch.setenv("DASHBOARD_PASSWORD", "pässwort")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("DEBUG", "true")

    from fastapi.testclient import TestClient

    from api.config import get_settings
    from api.main import create_app

    get_settings.cache_clear()
    app = create_app()
    with TestClient(app) as test_client:
        response = test_client.post(
            "/login", data={"password": "pässwort"}, follow_redirects=False
        )
        assert response.status_code == 303

    get_settings.cache_clear()


def test_out_of_range_threshold_shows_an_error(signed_in):
    response = signed_in.post(
        "/", data={"html": "<html><body></body></html>", "threshold": "-1"}
    )
    assert response.status_code == 200
    assert "between 0 and 1" in response.text


def test_dashboard_form_reflects_a_custom_default_threshold(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "api.db"))
    monkeypatch.setenv("DASHBOARD_PASSWORD", "test-password")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("DEBUG", "true")
    monkeypatch.setenv("DEFAULT_THRESHOLD", "0.50")

    from fastapi.testclient import TestClient

    from api.config import get_settings
    from api.main import create_app

    get_settings.cache_clear()
    app = create_app()
    with TestClient(app) as test_client:
        test_client.post("/login", data={"password": "test-password"})
        response = test_client.get("/")
        assert 'value="0.50"' in response.text

    get_settings.cache_clear()


def test_uploading_a_non_html_file_shows_an_error(signed_in):
    response = signed_in.post(
        "/",
        files={"file": ("malware.exe", b"MZ\x90\x00", "application/octet-stream")},
    )
    assert response.status_code == 200
    assert "Only .html and .htm files can be scanned" in response.text
