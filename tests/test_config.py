import pytest

from api.config import Settings, get_settings


def test_defaults_match_the_spec(monkeypatch):
    monkeypatch.setenv("DASHBOARD_PASSWORD", "pw")
    monkeypatch.setenv("SECRET_KEY", "sk")
    get_settings.cache_clear()

    s = get_settings()

    assert s.model_path == "phishing_html_model.joblib"
    assert s.default_threshold == 0.30
    assert s.max_body_bytes == 5242880
    assert s.max_redirects == 3
    assert s.small_site_tag_threshold == 150
    assert s.store_raw_html is False


def test_missing_required_secrets_raise(monkeypatch):
    monkeypatch.delenv("DASHBOARD_PASSWORD", raising=False)
    monkeypatch.delenv("SECRET_KEY", raising=False)
    get_settings.cache_clear()

    with pytest.raises(RuntimeError, match="DASHBOARD_PASSWORD"):
        get_settings()


def test_booleans_accept_common_spellings(monkeypatch):
    monkeypatch.setenv("DASHBOARD_PASSWORD", "pw")
    monkeypatch.setenv("SECRET_KEY", "sk")
    for raw in ("true", "True", "1", "yes"):
        monkeypatch.setenv("STORE_RAW_HTML", raw)
        get_settings.cache_clear()
        assert get_settings().store_raw_html is True
    for raw in ("false", "False", "0", "no", ""):
        monkeypatch.setenv("STORE_RAW_HTML", raw)
        get_settings.cache_clear()
        assert get_settings().store_raw_html is False


def test_settings_is_immutable(monkeypatch):
    monkeypatch.setenv("DASHBOARD_PASSWORD", "pw")
    monkeypatch.setenv("SECRET_KEY", "sk")
    get_settings.cache_clear()
    s = get_settings()
    with pytest.raises(Exception):
        s.default_threshold = 0.9
