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
