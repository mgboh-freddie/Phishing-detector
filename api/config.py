"""Environment-driven settings. Read once, cached, immutable."""

import os
from dataclasses import dataclass, field
from functools import lru_cache

from dotenv import find_dotenv, load_dotenv

# Populates os.environ from a .env file found by walking up from the
# current working directory. Real environment variables already set take
# precedence -- that is load_dotenv's default, so override is deliberately
# not passed. usecwd=True anchors the search on cwd rather than this
# file's location, which is what "run it from the project root" means in
# practice, for both the app and the tests that exercise this.
load_dotenv(find_dotenv(usecwd=True))

TRUTHY = {"1", "true", "yes", "on"}


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in TRUTHY


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(
            f"{name} is not set. Copy .env.example to .env and fill it in."
        )
    return value


@dataclass(frozen=True)
class Settings:
    model_path: str
    db_path: str
    default_threshold: float
    max_body_bytes: int
    fetch_connect_timeout: float
    fetch_read_timeout: float
    max_redirects: int
    small_site_tag_threshold: int
    store_raw_html: bool
    # repr=False on all three: Settings appears in traceback frames, and
    # the catch-all error handler logs tracebacks. Without this, one
    # unhandled exception writes every secret into the log.
    dashboard_password: str = field(repr=False)
    secret_key: str = field(repr=False)
    debug: bool
    bootstrap_api_key: str = field(default="", repr=False)
    bootstrap_api_key_name: str = "bootstrap"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings(
        model_path=os.environ.get("MODEL_PATH", "phishing_html_model.joblib"),
        db_path=os.environ.get("DB_PATH", "data/api.db"),
        default_threshold=float(os.environ.get("DEFAULT_THRESHOLD", "0.30")),
        max_body_bytes=int(os.environ.get("MAX_BODY_BYTES", "5242880")),
        fetch_connect_timeout=float(os.environ.get("FETCH_CONNECT_TIMEOUT", "5")),
        fetch_read_timeout=float(os.environ.get("FETCH_READ_TIMEOUT", "10")),
        max_redirects=int(os.environ.get("MAX_REDIRECTS", "3")),
        small_site_tag_threshold=int(os.environ.get("SMALL_SITE_TAG_THRESHOLD", "400")),
        store_raw_html=_bool("STORE_RAW_HTML", False),
        dashboard_password=_required("DASHBOARD_PASSWORD"),
        secret_key=_required("SECRET_KEY"),
        debug=_bool("DEBUG", False),
        bootstrap_api_key=os.environ.get("BOOTSTRAP_API_KEY", ""),
        bootstrap_api_key_name=os.environ.get("BOOTSTRAP_API_KEY_NAME", "bootstrap"),
    )
