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
    assert s.small_site_tag_threshold == 400
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


def test_dotenv_file_is_loaded(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("DASHBOARD_PASSWORD", raising=False)
    monkeypatch.delenv("SECRET_KEY", raising=False)
    (tmp_path / ".env").write_text(
        "DASHBOARD_PASSWORD=from-dotenv\nSECRET_KEY=from-dotenv-secret\n",
        encoding="utf-8",
    )

    import api.config as config

    config.load_dotenv(config.find_dotenv(usecwd=True))
    get_settings.cache_clear()

    s = get_settings()

    assert s.dashboard_password == "from-dotenv"
    assert s.secret_key == "from-dotenv-secret"


def test_real_environment_variable_beats_dotenv_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DASHBOARD_PASSWORD", "from-real-env")
    monkeypatch.setenv("SECRET_KEY", "from-real-env-secret")
    (tmp_path / ".env").write_text(
        "DASHBOARD_PASSWORD=from-dotenv\nSECRET_KEY=from-dotenv-secret\n",
        encoding="utf-8",
    )

    import api.config as config

    config.load_dotenv(config.find_dotenv(usecwd=True))
    get_settings.cache_clear()

    s = get_settings()

    assert s.dashboard_password == "from-real-env"
