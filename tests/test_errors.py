"""The error envelope must cover the whole API, not just the routes that
raise our own exception types."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.errors import register_error_handlers


def test_unknown_route_returns_404_in_the_envelope_shape(client):
    response = client.get("/v1/nope")

    assert response.status_code == 404
    body = response.json()
    assert body["error"]["code"] == "not_found"
    assert isinstance(body["error"]["message"], str)


def test_wrong_method_on_a_real_route_returns_405_in_the_envelope_shape(client):
    response = client.delete("/v1/scan")

    assert response.status_code == 405
    body = response.json()
    assert body["error"]["code"] == "method_not_allowed"
    assert isinstance(body["error"]["message"], str)


def test_unhandled_exception_returns_generic_500_without_leaking_details():
    """This service parses attacker-supplied HTML, so an exception message
    could contain page fragments or internal paths. The client must never
    see the raw exception text."""
    app = FastAPI()
    register_error_handlers(app)

    @app.get("/boom")
    def boom():
        raise RuntimeError("leaked internal path: /etc/secret-config.yaml")

    with TestClient(app, raise_server_exceptions=False) as test_client:
        response = test_client.get("/boom")

    assert response.status_code == 500
    body = response.json()
    assert body["error"]["code"] == "internal_error"
    assert isinstance(body["error"]["message"], str)
    assert "leaked internal path" not in response.text
    assert "/etc/secret-config.yaml" not in response.text
