# Phishing Detector API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wrap the existing HTML phishing scanner in a FastAPI service exposing a key-authenticated JSON API and a minimal single-user dashboard.

**Architecture:** `extract_features.py` is tested and stays untouched; every new module lives under `api/`. The model bundle loads once at startup and is held in memory. Both the JSON API and the dashboard call the same `scoring.score_html`, so they cannot drift apart. Untrusted URL fetching is isolated in `fetching.py`, which is the single control point for SSRF defence.

**Tech Stack:** Python 3.11+, FastAPI, uvicorn, Pydantic v2, Jinja2, stdlib `sqlite3`, `requests`, pytest, httpx (test client).

## Global Constraints

- **Python 3.11 or newer is mandatory.** The model bundle was pickled with scikit-learn 1.8.0, which does not publish wheels for Python 3.10. Running on 3.10 forces scikit-learn 1.7.2 and produces `InconsistentVersionWarning: ... might lead to breaking code or invalid results` on every load.
- **Pin `scikit-learn==1.8.0`.** Any other version risks different predictions from the same bundle.
- `extract_features.py`, `scan.py`, `collect.py`, and `phishing_html_model.joblib` are **not modified by this plan**.
- Feature order must always come from `extract_features.FEATURE_ORDER`. Never hard-code the 13 names anywhere else.
- Downloaded pages are **never rendered or executed**. No headless browser, no `eval`, no JS engine. Parsing is BeautifulSoup only.
- Default threshold `0.30`. Max body `5242880` bytes (5 MB). Connect timeout `5`s, read timeout `10`s, max redirects `3`. Small-site warning fires under `400` tags. Default rate limit `60`/minute.
- API key format: `sk_live_` + 32 URL-safe random chars, stored only as SHA-256.
- Raw HTML is **not** persisted unless `STORE_RAW_HTML=true`.
- Verdict strings in JSON are lowercase: `phishing` / `benign`.
- All timestamps stored and returned as UTC ISO-8601 with a trailing `Z`.
- Every JSON error response uses the shape `{"error": {"code": "...", "message": "..."}}`.
- Commit after every task. Never add a `Co-Authored-By` trailer.

---

### Task 1: Environment, configuration, and dependency pinning

Fixes the two environment defects found before planning: `lxml` is missing (so `extract_features.py` cannot run at all) and scikit-learn does not match the pickled model.

**Files:**
- Create: `requirements.txt`
- Create: `.env.example`
- Create: `api/__init__.py`
- Create: `api/config.py`
- Create: `tests/__init__.py`
- Create: `tests/test_config.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `api.config.Settings` dataclass with fields `model_path: str`, `db_path: str`, `default_threshold: float`, `max_body_bytes: int`, `fetch_connect_timeout: float`, `fetch_read_timeout: float`, `max_redirects: int`, `small_site_tag_threshold: int`, `store_raw_html: bool`, `dashboard_password: str`, `secret_key: str`, `debug: bool`. Module function `api.config.get_settings() -> Settings` (cached).

- [ ] **Step 1: Confirm the Python version**

Run: `py -3.11 -V` (or `py -3.12 -V`)
Expected: `Python 3.11.x` or newer.

If neither exists, install Python 3.12 from python.org, ticking **"Add Python to PATH"**. Everything below assumes `py -3.12` — substitute your version consistently.

- [ ] **Step 2: Create a virtual environment on the correct interpreter**

```bash
py -3.12 -m venv .venv
```

Activate it. PowerShell: `.venv\Scripts\Activate.ps1`. cmd: `.venv\Scripts\activate.bat`. Git Bash: `source .venv/Scripts/activate`.

Run: `python -V`
Expected: `Python 3.12.x`. If it still says 3.10, the venv is not active — stop and fix that before continuing.

- [ ] **Step 3: Write `requirements.txt`**

```
# Pinned to the version the model bundle was pickled with. Any other
# version risks silently different predictions from the same model.
scikit-learn==1.8.0

fastapi==0.136.1
uvicorn[standard]==0.47.0
pydantic==2.12.5
jinja2==3.1.6
python-multipart>=0.0.9
requests==2.32.5
beautifulsoup4==4.14.3
lxml>=5.2
joblib==1.5.3
pandas==2.3.3

pytest==9.0.2
httpx>=0.27
```

- [ ] **Step 4: Install and verify the model loads without warnings**

```bash
python -m pip install -r requirements.txt
```

Then run this — it is the check that the environment is actually correct:

```bash
python -W error::UserWarning -c "import joblib; b=joblib.load('phishing_html_model.joblib'); print('clean load, features:', len(b['features']))"
```

Expected: `clean load, features: 13` with no traceback.
If it raises `InconsistentVersionWarning`, the scikit-learn pin did not take effect — do not continue, fix it first.

- [ ] **Step 5: Verify the extractor now runs end to end**

```bash
python scan.py data/realistic_benign.html
```

Expected: a line reporting roughly `0.365 PHISHING realistic_benign.html`. Record the exact score — Task 2 asserts against it.

If this raises `FeatureNotFound: Couldn't find a tree builder ... lxml`, `lxml` did not install.

- [ ] **Step 6: Write `.env.example`**

```
# Model bundle. Swap this for a retrained bundle with the same 13 features
# and no code change is needed.
MODEL_PATH=phishing_html_model.joblib

DB_PATH=data/api.db
DEFAULT_THRESHOLD=0.30

# 5 MB
MAX_BODY_BYTES=5242880
FETCH_CONNECT_TIMEOUT=5
FETCH_READ_TIMEOUT=10
MAX_REDIRECTS=3

# Below this tag count, a phishing verdict carries the small_simple_site
# warning. Under the 514-tag median of benign training pages, and over the
# 357 tags of the bakery fixture the README calls out as the known false
# positive — so the page the project already knows is misjudged is covered.
SMALL_SITE_TAG_THRESHOLD=400

# Attacker-controlled content. Enable only for deliberate data collection.
STORE_RAW_HTML=false

# Both required. The app refuses to start without them.
DASHBOARD_PASSWORD=change-me
SECRET_KEY=generate-with-python-c-import-secrets-print-secrets-token-urlsafe-32

DEBUG=true
```

- [ ] **Step 7: Write the failing test**

Create `tests/__init__.py` as an empty file, then `tests/test_config.py`:

```python
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
```

- [ ] **Step 8: Run it to make sure it fails**

Run: `python -m pytest tests/test_config.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'api.config'`.

- [ ] **Step 9: Write `api/config.py`**

Create `api/__init__.py` as an empty file, then:

```python
"""Environment-driven settings. Read once, cached, immutable."""

import os
from dataclasses import dataclass
from functools import lru_cache

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
    dashboard_password: str
    secret_key: str
    debug: bool


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
    )
```

- [ ] **Step 10: Run the tests and make sure they pass**

Run: `python -m pytest tests/test_config.py -v`
Expected: 4 passed.

- [ ] **Step 11: Commit**

```bash
git add requirements.txt .env.example api/__init__.py api/config.py tests/
git commit -m "feat(api): pin dependencies and add env-driven settings

Pins scikit-learn to 1.8.0, the version the model bundle was pickled
with. Loading it under 1.7.2 warned that results might be invalid,
which is not an acceptable footing for a detector. That pin requires
Python 3.11+, since 1.8.0 publishes no wheels for 3.10.

Also adds lxml, without which extract_features.py could not run at all."
```

---

### Task 2: Scoring service

Wraps the model. Keeps the feature-order guard from `scan.py:43`, which is the check that stops a silent extractor/model drift turning every prediction into noise.

**Files:**
- Create: `api/scoring.py`
- Create: `tests/test_scoring.py`

**Interfaces:**
- Consumes: `api.config.Settings`.
- Produces:
  - `api.scoring.Bundle` — frozen dataclass with `model`, `threshold: float`, `features: list[str]`, `version: str`.
  - `api.scoring.load_bundle(path: str) -> Bundle` — raises `RuntimeError` on feature mismatch.
  - `api.scoring.score_html(bundle: Bundle, html: str, page_url: str | None = None) -> tuple[float, dict[str, float]]` — returns `(score, features)`.
  - `api.scoring.verdict_for(score: float, threshold: float) -> str` — `"phishing"` or `"benign"`.
  - `api.scoring.build_warnings(features: dict, verdict: str, tag_threshold: int) -> list[str]`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_scoring.py`:

```python
import pytest

from api.scoring import (
    Bundle,
    build_warnings,
    load_bundle,
    score_html,
    verdict_for,
)

BENIGN_FIXTURE = "data/realistic_benign.html"
PHISHY_FIXTURE = "data/phishy.html"


@pytest.fixture(scope="module")
def bundle():
    return load_bundle("phishing_html_model.joblib")


def read(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def test_bundle_exposes_threshold_and_version(bundle):
    assert bundle.threshold == 0.30
    assert len(bundle.features) == 13
    assert len(bundle.version) > 0


def test_missing_model_file_raises():
    with pytest.raises(RuntimeError, match="Model not found"):
        load_bundle("no_such_model.joblib")


def test_feature_mismatch_raises(bundle, monkeypatch, tmp_path):
    import joblib

    bad = {
        "model": bundle.model,
        "threshold": 0.3,
        "features": ["wrong_feature"],
    }
    path = tmp_path / "bad.joblib"
    joblib.dump(bad, path)

    with pytest.raises(RuntimeError, match="Feature mismatch"):
        load_bundle(str(path))


def test_phishy_fixture_scores_higher_than_benign(bundle):
    phishy, _ = score_html(bundle, read(PHISHY_FIXTURE))
    benign, _ = score_html(bundle, read(BENIGN_FIXTURE))
    assert phishy > benign


def test_score_returns_all_thirteen_features(bundle):
    from extract_features import FEATURE_ORDER

    _, features = score_html(bundle, read(PHISHY_FIXTURE))
    assert set(features) == set(FEATURE_ORDER)


def test_scoring_matches_scan_py_exactly(bundle):
    """Success criterion 3: the API must not change the product's answers."""
    import pandas as pd

    from extract_features import extract_from_file

    expected_features = extract_from_file(PHISHY_FIXTURE)
    X = pd.DataFrame([expected_features])[bundle.features]
    expected_score = float(bundle.model.predict_proba(X)[:, 1][0])

    actual_score, actual_features = score_html(bundle, read(PHISHY_FIXTURE))

    assert actual_score == expected_score
    assert actual_features == expected_features


def test_page_url_changes_link_classification(bundle):
    html = '<html><body><a href="https://example.com/a">x</a></body></html>'
    _, without = score_html(bundle, html)
    _, with_url = score_html(bundle, html, page_url="https://example.com/")

    assert without["external_link_count"] == 1
    assert with_url["internal_link_count"] == 1


def test_verdict_uses_threshold_inclusively():
    assert verdict_for(0.30, 0.30) == "phishing"
    assert verdict_for(0.2999, 0.30) == "benign"


def test_small_simple_site_warning_fires_on_the_bakery_page(bundle):
    """The documented bias must be visible, not hidden."""
    score, features = score_html(bundle, read(BENIGN_FIXTURE))
    v = verdict_for(score, 0.30)
    warnings = build_warnings(features, v, tag_threshold=400)

    assert v == "phishing"
    assert "small_simple_site" in warnings


def test_no_warning_when_verdict_is_benign():
    features = {"tag_count": 10, "min_link_length": 5}
    assert build_warnings(features, "benign", tag_threshold=400) == []


def test_no_links_found_warning():
    features = {"tag_count": 900, "min_link_length": 0}
    assert "no_links_found" in build_warnings(features, "benign", tag_threshold=400)
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `python -m pytest tests/test_scoring.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'api.scoring'`.

- [ ] **Step 3: Write `api/scoring.py`**

```python
"""Model loading and prediction.

The feature-order guard here is the important part. If the extractor's
FEATURE_ORDER ever drifts from the order the model was trained on,
predictions become meaningless without anything raising an error.
Refusing to start is the only safe response.
"""

import hashlib
import os
from dataclasses import dataclass
from typing import Any

import joblib
import pandas as pd

from extract_features import FEATURE_ORDER, extract_features


@dataclass(frozen=True)
class Bundle:
    model: Any
    threshold: float
    features: list
    version: str


def _file_version(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()[:12]


def load_bundle(path: str) -> Bundle:
    if not os.path.exists(path):
        raise RuntimeError(
            f"Model not found at {path}. Set MODEL_PATH to the bundle location."
        )

    raw = joblib.load(path)
    features = list(raw["features"])

    if features != list(FEATURE_ORDER):
        raise RuntimeError(
            "Feature mismatch between extractor and model.\n"
            f"  model expects:   {features}\n"
            f"  extractor gives: {list(FEATURE_ORDER)}\n"
            "Predictions would be meaningless. Refusing to start."
        )

    # The bundle carries no version key, so identify it by content hash.
    version = raw.get("version") or _file_version(path)

    return Bundle(
        model=raw["model"],
        threshold=float(raw["threshold"]),
        features=features,
        version=version,
    )


def score_html(bundle: Bundle, html: str, page_url: str = None):
    """Return (phishing_probability, features) for a page."""
    features = extract_features(html, page_url=page_url)
    X = pd.DataFrame([features])[bundle.features]
    score = float(bundle.model.predict_proba(X)[:, 1][0])
    return score, features


def verdict_for(score: float, threshold: float) -> str:
    return "phishing" if score >= threshold else "benign"


def build_warnings(features: dict, verdict: str, tag_threshold: int) -> list:
    """Surface known model limitations at the point of use.

    The model was trained on benign pages with a median 514 tags and
    malicious pages with 91, so it has partly learned "small and simple
    means phishing". Small business sites are both our intended customer
    and our blind spot, so a flag on a small page gets an explicit caveat.
    """
    warnings = []

    if verdict == "phishing" and features.get("tag_count", 0) < tag_threshold:
        warnings.append("small_simple_site")

    if features.get("min_link_length", 0) == 0:
        warnings.append("no_links_found")

    return warnings
```

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `python -m pytest tests/test_scoring.py -v`
Expected: 11 passed.

If `test_small_simple_site_warning_fires_on_the_bakery_page` fails because the verdict is `benign`, the score has moved away from the documented 0.365 — that means the environment is still wrong. Go back to Task 1 Step 4.

- [ ] **Step 5: Commit**

```bash
git add api/scoring.py tests/test_scoring.py
git commit -m "feat(api): add scoring service with feature-order guard

Keeps scan.py's guard against extractor/model drift and adds a parity
test proving the API scores identically to the CLI.

build_warnings surfaces the documented small-site bias rather than
returning a confident wrong answer. The bakery fixture is the test
case: still flagged, but now flagged with a caveat."
```

---

### Task 3: SSRF-hardened URL fetching

The security-critical task. Accepting a URL means a stranger chooses what address our server connects to.

**Files:**
- Create: `api/fetching.py`
- Create: `tests/test_fetching.py`

**Interfaces:**
- Consumes: `api.config.Settings`.
- Produces:
  - `api.fetching.FetchResult` — frozen dataclass with `html: str`, `final_url: str`, `tls_verified: bool`, `truncated: bool`.
  - `api.fetching.FetchError(Exception)` with attributes `code: str` and `status: int`; subclasses `InvalidURL` (400/`invalid_url`), `BlockedURL` (403/`url_blocked`), `UnsupportedContentType` (415/`unsupported_content_type`), `FetchFailed` (502/`fetch_failed`), `FetchTimeout` (504/`fetch_timeout`).
  - `api.fetching.validate_url(url: str) -> str` — returns the URL with credentials stripped.
  - `api.fetching.is_blocked_ip(ip: str) -> bool`.
  - `api.fetching.fetch(url: str, settings: Settings) -> FetchResult`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_fetching.py`:

```python
import pytest

from api.fetching import BlockedURL, InvalidURL, is_blocked_ip, validate_url


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.com/x",
        "gopher://example.com/",
        "javascript:alert(1)",
        "not a url",
        "",
    ],
)
def test_non_http_schemes_are_refused(url):
    with pytest.raises(InvalidURL):
        validate_url(url)


def test_overlong_url_is_refused():
    with pytest.raises(InvalidURL):
        validate_url("https://example.com/" + "a" * 2100)


def test_credentials_are_stripped():
    assert validate_url("https://user:pw@example.com/x") == "https://example.com/x"


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",          # loopback
        "10.0.0.1",           # private
        "172.16.0.1",         # private
        "192.168.1.1",        # private
        "169.254.169.254",    # cloud metadata endpoint — the one that matters
        "100.64.0.1",         # CGNAT
        "0.0.0.0",            # unspecified
        "224.0.0.1",          # multicast
        "::1",                # IPv6 loopback
        "fc00::1",            # IPv6 unique-local
        "fe80::1",            # IPv6 link-local
        "::ffff:127.0.0.1",   # IPv4-mapped loopback
    ],
)
def test_internal_addresses_are_blocked(ip):
    assert is_blocked_ip(ip) is True


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_addresses_are_allowed(ip):
    assert is_blocked_ip(ip) is False


def test_hostname_resolving_to_loopback_is_blocked(monkeypatch):
    import api.fetching as f

    monkeypatch.setattr(f, "resolve_host", lambda host: ["127.0.0.1"])
    with pytest.raises(BlockedURL):
        f.guard_url("http://evil.test/")


def test_redirect_to_private_address_is_blocked(monkeypatch):
    """The standard bypass: a public URL that 302s somewhere internal."""
    import api.fetching as f
    from api.config import Settings

    settings = Settings(
        model_path="x", db_path=":memory:", default_threshold=0.3,
        max_body_bytes=5242880, fetch_connect_timeout=5, fetch_read_timeout=10,
        max_redirects=3, small_site_tag_threshold=400, store_raw_html=False,
        dashboard_password="pw", secret_key="sk", debug=True,
    )

    hosts = {"public.test": ["8.8.8.8"], "internal.test": ["10.0.0.5"]}
    monkeypatch.setattr(f, "resolve_host", lambda host: hosts[host])

    class FakeResponse:
        status_code = 302
        headers = {"Location": "http://internal.test/secrets"}
        url = "http://public.test/"

        def close(self):
            pass

    monkeypatch.setattr(f, "_request", lambda url, settings, verify: (FakeResponse(), True))

    with pytest.raises(BlockedURL):
        f.fetch("http://public.test/", settings)
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `python -m pytest tests/test_fetching.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'api.fetching'`.

- [ ] **Step 3: Write `api/fetching.py`**

```python
"""Fetching caller-supplied URLs.

An untrusted party chooses the address our server connects to, which is
the definition of SSRF. Unguarded, someone POSTs the cloud metadata
endpoint and the API cheerfully returns our own credentials as features.

Everything here exists to prevent that. Note also that pages are never
rendered or executed — the response body is parsed as text and nothing
more, which is the whole reason the underlying research uses static
features.
"""

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = ("http", "https")
ALLOWED_CONTENT_TYPES = ("text/html", "application/xhtml+xml", "text/plain")

# Not covered by ipaddress's own predicates on every Python version, so
# checked explicitly rather than assumed.
EXTRA_BLOCKED_V4 = (ipaddress.ip_network("100.64.0.0/10"),)


class FetchError(Exception):
    code = "fetch_failed"
    status = 502


class InvalidURL(FetchError):
    code = "invalid_url"
    status = 400


class BlockedURL(FetchError):
    code = "url_blocked"
    status = 403


class UnsupportedContentType(FetchError):
    code = "unsupported_content_type"
    status = 415


class FetchFailed(FetchError):
    code = "fetch_failed"
    status = 502


class FetchTimeout(FetchError):
    code = "fetch_timeout"
    status = 504


@dataclass(frozen=True)
class FetchResult:
    html: str
    final_url: str
    tls_verified: bool
    truncated: bool


def validate_url(url: str) -> str:
    """Check scheme and length, strip credentials. Returns a clean URL."""
    if not url or len(url) > MAX_URL_LENGTH:
        raise InvalidURL("URL is empty or longer than 2048 characters.")

    parts = urlsplit(url.strip())

    if parts.scheme not in ALLOWED_SCHEMES:
        raise InvalidURL("Only http and https URLs can be scanned.")
    if not parts.hostname:
        raise InvalidURL("URL has no hostname.")

    # Drop any user:password@ before the request is ever made.
    netloc = parts.hostname
    if parts.port:
        netloc = f"{netloc}:{parts.port}"

    return urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, ""))


def is_blocked_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True

    # Unwrap ::ffff:127.0.0.1 style addresses before judging them.
    if getattr(addr, "ipv4_mapped", None):
        addr = addr.ipv4_mapped

    if (
        addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    ):
        return True

    if addr.version == 4 and any(addr in net for net in EXTRA_BLOCKED_V4):
        return True

    return False


def resolve_host(host: str) -> list:
    """Every address the hostname resolves to. Separate function so tests
    can substitute it."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise FetchFailed(f"Could not resolve {host}.") from exc
    return [info[4][0] for info in infos]


def guard_url(url: str) -> str:
    """Validate a URL and refuse it if any resolved address is internal."""
    clean = validate_url(url)
    host = urlsplit(clean).hostname

    addresses = resolve_host(host)
    if not addresses:
        raise FetchFailed(f"Could not resolve {host}.")

    for ip in addresses:
        if is_blocked_ip(ip):
            raise BlockedURL("URL resolves to a private or reserved address.")

    return clean


def _request(url: str, settings, verify: bool):
    """One HTTP GET. Returns (response, tls_verified)."""
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
        )
    }
    timeout = (settings.fetch_connect_timeout, settings.fetch_read_timeout)
    return (
        requests.get(
            url,
            headers=headers,
            timeout=timeout,
            stream=True,
            allow_redirects=False,
            verify=verify,
        ),
        verify,
    )


def _get_with_tls_fallback(url: str, settings):
    """Verified first; fall back unverified and report which happened.

    Broken certificates are normal on phishing sites, so strict-only
    checking would refuse exactly the pages this product exists to
    examine. Safe only because the content is never executed.
    """
    try:
        return _request(url, settings, verify=True)
    except requests.exceptions.SSLError:
        return _request(url, settings, verify=False)


def _read_capped(response, limit: int):
    """Stream the body, stopping at the cap. Returns (text, truncated)."""
    chunks = []
    total = 0
    truncated = False

    for chunk in response.iter_content(chunk_size=65536):
        if not chunk:
            continue
        chunks.append(chunk)
        total += len(chunk)
        if total >= limit:
            truncated = True
            break

    body = b"".join(chunks)[:limit]
    encoding = response.encoding or "utf-8"
    return body.decode(encoding, errors="replace"), truncated


def fetch(url: str, settings) -> FetchResult:
    current = guard_url(url)
    tls_verified = True

    for _ in range(settings.max_redirects + 1):
        try:
            response, tls_verified = _get_with_tls_fallback(current, settings)
        except requests.exceptions.Timeout as exc:
            raise FetchTimeout("The page took too long to respond.") from exc
        except requests.exceptions.RequestException as exc:
            raise FetchFailed(f"Could not fetch the page: {exc}") from exc

        if 300 <= response.status_code < 400 and response.headers.get("Location"):
            target = urljoin(current, response.headers["Location"])
            response.close()
            # Re-validate every hop. A public URL redirecting to
            # 127.0.0.1 is the standard way round a single check.
            current = guard_url(target)
            continue

        try:
            if response.status_code >= 400:
                raise FetchFailed(f"Page returned HTTP {response.status_code}.")

            content_type = response.headers.get("Content-Type", "").split(";")[0].strip()
            if content_type and content_type not in ALLOWED_CONTENT_TYPES:
                raise UnsupportedContentType(
                    f"Expected HTML, got {content_type}."
                )

            html, truncated = _read_capped(response, settings.max_body_bytes)
        finally:
            response.close()

        return FetchResult(
            html=html,
            final_url=current,
            tls_verified=tls_verified,
            truncated=truncated,
        )

    raise FetchFailed("Too many redirects.")
```

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `python -m pytest tests/test_fetching.py -v`
Expected: 25 passed.

- [ ] **Step 5: Record the known gap as a code comment**

Add directly above `def guard_url` in `api/fetching.py`:

```python
# KNOWN GAP (v2): resolve-then-connect leaves a DNS-rebinding window —
# the hostname can resolve to a public address here and an internal one
# by the time requests opens the socket. Closing it means pinning the
# connection to the validated IP while preserving SNI and the Host
# header, via a custom transport adapter. Recorded rather than hidden.
```

- [ ] **Step 6: Commit**

```bash
git add api/fetching.py tests/test_fetching.py
git commit -m "feat(api): add SSRF-hardened URL fetching

Fetching a caller-supplied URL points our own server at an address a
stranger picked. Guards: scheme allowlist, credentials stripped,
resolve-and-reject for private and reserved ranges including IPv6 and
IPv4-mapped forms, every redirect hop re-validated, and caps on size,
time, and content type.

The 169.254.169.254 case has its own test. Fetching the cloud metadata
endpoint on request is the difference between a service and an incident.

TLS verification is attempted first and falls back, reporting which
happened, because broken certificates are normal on phishing sites."
```

---

### Task 4: SQLite storage

**Files:**
- Create: `api/store.py`
- Create: `tests/test_store.py`

**Interfaces:**
- Consumes: `api.config.Settings`.
- Produces:
  - `api.store.new_id(prefix: str) -> str` — e.g. `scn_01hq8z…`, time-ordered.
  - `api.store.init_db(db_path: str) -> None` — creates tables, idempotent.
  - `api.store.connect(db_path: str)` — context manager yielding a `sqlite3.Connection` with `row_factory` set.
  - `api.store.create_key(db_path, name, threshold=None, rate_limit=60) -> tuple[str, str]` — returns `(key_id, plaintext_key)`.
  - `api.store.find_key_by_hash(db_path, key_hash) -> sqlite3.Row | None`.
  - `api.store.list_keys(db_path) -> list[sqlite3.Row]`.
  - `api.store.revoke_key(db_path, key_id) -> bool`.
  - `api.store.touch_key(db_path, key_id) -> None`.
  - `api.store.hash_key(plaintext: str) -> str`.
  - `api.store.utcnow() -> str` — UTC ISO-8601 with a trailing `Z`.
  - `api.store.ensure_internal_key(db_path, threshold: float) -> None`.
  - `api.store.save_scan(db_path, record: dict, store_raw_html: bool) -> None`.
  - `api.store.list_scans(db_path, key_id, limit=50, offset=0) -> list[dict]`.
  - `api.store.count_scans(db_path, key_id) -> int`.
  - `api.store.get_scan(db_path, key_id, scan_id) -> dict | None`.
  - `api.store.INTERNAL_KEY_ID: str` — the reserved dashboard key id.

- [ ] **Step 1: Write the failing test**

Create `tests/test_store.py`:

```python
import pytest

from api import store


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "test.db")
    store.init_db(path)
    return path


def test_init_db_is_idempotent(db):
    store.init_db(db)
    store.init_db(db)


def test_ids_are_prefixed_and_strictly_increasing():
    """Two ids created in the same millisecond must still sort correctly,
    or 'newest first' ordering is unreliable."""
    ids = [store.new_id("scn") for _ in range(50)]

    assert all(i.startswith("scn_") for i in ids)
    assert len(set(ids)) == 50
    assert ids == sorted(ids)


def test_create_key_returns_plaintext_once_and_stores_only_a_hash(db):
    key_id, plaintext = store.create_key(db, "sam")

    assert plaintext.startswith("sk_live_")
    assert len(plaintext) > 20

    with store.connect(db) as conn:
        row = conn.execute(
            "SELECT key_hash FROM api_keys WHERE id = ?", (key_id,)
        ).fetchone()

    assert plaintext not in row["key_hash"]
    assert row["key_hash"] == store.hash_key(plaintext)


def test_find_key_by_hash_round_trips(db):
    key_id, plaintext = store.create_key(db, "sam", threshold=0.5, rate_limit=10)

    row = store.find_key_by_hash(db, store.hash_key(plaintext))

    assert row["id"] == key_id
    assert row["name"] == "sam"
    assert row["threshold"] == 0.5
    assert row["rate_limit"] == 10
    assert row["revoked_at"] is None


def test_unknown_hash_returns_none(db):
    assert store.find_key_by_hash(db, "deadbeef") is None


def test_revoke_marks_the_key(db):
    key_id, plaintext = store.create_key(db, "sam")

    assert store.revoke_key(db, key_id) is True

    row = store.find_key_by_hash(db, store.hash_key(plaintext))
    assert row["revoked_at"] is not None


def test_revoking_an_unknown_key_returns_false(db):
    assert store.revoke_key(db, "key_nope") is False


def make_record(key_id, **overrides):
    record = {
        "id": store.new_id("scn"),
        "key_id": key_id,
        "source": "url",
        "target": "https://example.com/",
        "content_sha256": "a" * 64,
        "score": 0.69,
        "verdict": "phishing",
        "threshold": 0.30,
        "features": {"tag_count": 91},
        "warnings": ["small_simple_site"],
        "tls_verified": True,
        "model_version": "abc123",
        "elapsed_ms": 412,
        "raw_html": "<html></html>",
    }
    record.update(overrides)
    return record


def test_save_and_read_back_a_scan(db):
    key_id, _ = store.create_key(db, "sam")
    record = make_record(key_id)

    store.save_scan(db, record, store_raw_html=False)
    fetched = store.get_scan(db, key_id, record["id"])

    assert fetched["score"] == 0.69
    assert fetched["verdict"] == "phishing"
    assert fetched["features"] == {"tag_count": 91}
    assert fetched["warnings"] == ["small_simple_site"]
    assert fetched["tls_verified"] is True


def test_raw_html_is_not_stored_by_default(db):
    key_id, _ = store.create_key(db, "sam")
    record = make_record(key_id)

    store.save_scan(db, record, store_raw_html=False)

    with store.connect(db) as conn:
        row = conn.execute(
            "SELECT raw_html FROM scans WHERE id = ?", (record["id"],)
        ).fetchone()
    assert row["raw_html"] is None


def test_raw_html_is_stored_when_enabled(db):
    key_id, _ = store.create_key(db, "sam")
    record = make_record(key_id)

    store.save_scan(db, record, store_raw_html=True)

    with store.connect(db) as conn:
        row = conn.execute(
            "SELECT raw_html FROM scans WHERE id = ?", (record["id"],)
        ).fetchone()
    assert row["raw_html"] == "<html></html>"


def test_history_is_scoped_to_the_calling_key(db):
    mine, _ = store.create_key(db, "mine")
    theirs, _ = store.create_key(db, "theirs")

    store.save_scan(db, make_record(mine), store_raw_html=False)
    store.save_scan(db, make_record(theirs), store_raw_html=False)

    assert len(store.list_scans(db, mine)) == 1
    assert len(store.list_scans(db, theirs)) == 1


def test_another_keys_scan_is_not_readable(db):
    mine, _ = store.create_key(db, "mine")
    theirs, _ = store.create_key(db, "theirs")
    record = make_record(theirs)
    store.save_scan(db, record, store_raw_html=False)

    assert store.get_scan(db, mine, record["id"]) is None


def test_history_is_newest_first_and_paginates(db):
    key_id, _ = store.create_key(db, "sam")
    ids = []
    for _ in range(5):
        record = make_record(key_id)
        store.save_scan(db, record, store_raw_html=False)
        ids.append(record["id"])

    rows = store.list_scans(db, key_id, limit=2, offset=0)
    assert [r["id"] for r in rows] == [ids[4], ids[3]]

    rows = store.list_scans(db, key_id, limit=2, offset=2)
    assert [r["id"] for r in rows] == [ids[2], ids[1]]
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `python -m pytest tests/test_store.py -v`
Expected: FAIL — `ImportError: cannot import name 'store' from 'api'`.

- [ ] **Step 3: Write `api/store.py`**

```python
"""SQLite persistence for API keys and scan history.

A connection is opened per operation rather than shared. FastAPI runs
sync endpoints in a thread pool, and SQLite connections are not safe to
share across threads. Opening per call is cheap and removes the problem
entirely.
"""

import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone

# Dashboard scans are attributed here so history queries need no special
# case for "the scan had no API key".
INTERNAL_KEY_ID = "key_internal_dashboard"

CROCKFORD = "0123456789abcdefghjkmnpqrstvwxyz"

SCHEMA = """
CREATE TABLE IF NOT EXISTS api_keys (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  key_hash      TEXT NOT NULL UNIQUE,
  threshold     REAL NOT NULL DEFAULT 0.30,
  rate_limit    INTEGER NOT NULL DEFAULT 60,
  created_at    TEXT NOT NULL,
  last_used_at  TEXT,
  revoked_at    TEXT
);

CREATE TABLE IF NOT EXISTS scans (
  id             TEXT PRIMARY KEY,
  key_id         TEXT REFERENCES api_keys(id),
  source         TEXT NOT NULL,
  target         TEXT NOT NULL,
  content_sha256 TEXT NOT NULL,
  score          REAL NOT NULL,
  verdict        TEXT NOT NULL,
  threshold      REAL NOT NULL,
  features       TEXT NOT NULL,
  warnings       TEXT NOT NULL,
  tls_verified   INTEGER,
  model_version  TEXT NOT NULL,
  elapsed_ms     INTEGER NOT NULL,
  created_at     TEXT NOT NULL,
  raw_html       TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_key_created
  ON scans(key_id, created_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS rate_windows (
  key_id       TEXT NOT NULL,
  window_start TEXT NOT NULL,
  count        INTEGER NOT NULL,
  PRIMARY KEY (key_id, window_start)
);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


_sequence_lock = threading.Lock()
_last_stamp = [0, 0]  # [milliseconds, counter within that millisecond]


def _encode(value: int, width: int) -> str:
    out = ""
    for _ in range(width):
        out = CROCKFORD[value & 31] + out
        value >>= 5
    return out


def new_id(prefix: str) -> str:
    """Strictly increasing id: millisecond timestamp, then a counter, then
    randomness.

    The counter matters. Several scans can land in the same millisecond,
    and without it two ids from that millisecond would sort by their
    random tail — which would make 'newest first' ordering unreliable
    exactly when it is most likely to be tested.
    """
    with _sequence_lock:
        ms = int(time.time() * 1000)
        if ms == _last_stamp[0]:
            _last_stamp[1] += 1
        else:
            _last_stamp[0] = ms
            _last_stamp[1] = 0
        counter = _last_stamp[1]

    rand = "".join(secrets.choice(CROCKFORD) for _ in range(12))
    return f"{prefix}_{_encode(ms, 10)}{_encode(counter, 4)}{rand}"


@contextmanager
def connect(db_path: str):
    parent = os.path.dirname(db_path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(db_path: str) -> None:
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)


def hash_key(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def create_key(db_path: str, name: str, threshold=None, rate_limit: int = 60):
    """Create a key. The plaintext is returned once and never recoverable."""
    key_id = new_id("key")
    plaintext = "sk_live_" + secrets.token_urlsafe(24)[:32]

    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO api_keys (id, name, key_hash, threshold, rate_limit, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                key_id,
                name,
                hash_key(plaintext),
                0.30 if threshold is None else float(threshold),
                int(rate_limit),
                utcnow(),
            ),
        )
    return key_id, plaintext


def find_key_by_hash(db_path: str, key_hash: str):
    with connect(db_path) as conn:
        return conn.execute(
            "SELECT * FROM api_keys WHERE key_hash = ?", (key_hash,)
        ).fetchone()


def list_keys(db_path: str):
    with connect(db_path) as conn:
        return conn.execute(
            "SELECT id, name, threshold, rate_limit, created_at, last_used_at,"
            " revoked_at FROM api_keys ORDER BY created_at"
        ).fetchall()


def revoke_key(db_path: str, key_id: str) -> bool:
    with connect(db_path) as conn:
        cursor = conn.execute(
            "UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
            (utcnow(), key_id),
        )
        return cursor.rowcount > 0


def touch_key(db_path: str, key_id: str) -> None:
    with connect(db_path) as conn:
        conn.execute(
            "UPDATE api_keys SET last_used_at = ? WHERE id = ?", (utcnow(), key_id)
        )


def ensure_internal_key(db_path: str, threshold: float) -> None:
    """The dashboard's own key row. No plaintext exists for it, so the
    hash is a value no real key can hash to."""
    with connect(db_path) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO api_keys (id, name, key_hash, threshold,"
            " rate_limit, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                INTERNAL_KEY_ID,
                "dashboard",
                "internal-no-plaintext",
                float(threshold),
                100000,
                utcnow(),
            ),
        )


def save_scan(db_path: str, record: dict, store_raw_html: bool) -> None:
    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO scans (id, key_id, source, target, content_sha256, score,"
            " verdict, threshold, features, warnings, tls_verified, model_version,"
            " elapsed_ms, created_at, raw_html)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                record["id"],
                record["key_id"],
                record["source"],
                record["target"],
                record["content_sha256"],
                float(record["score"]),
                record["verdict"],
                float(record["threshold"]),
                json.dumps(record["features"]),
                json.dumps(record["warnings"]),
                None if record["tls_verified"] is None else int(record["tls_verified"]),
                record["model_version"],
                int(record["elapsed_ms"]),
                record.get("created_at") or utcnow(),
                record.get("raw_html") if store_raw_html else None,
            ),
        )


def _row_to_scan(row) -> dict:
    return {
        "id": row["id"],
        "source": row["source"],
        "target": row["target"],
        "score": row["score"],
        "verdict": row["verdict"],
        "threshold": row["threshold"],
        "features": json.loads(row["features"]),
        "warnings": json.loads(row["warnings"]),
        "tls_verified": None if row["tls_verified"] is None else bool(row["tls_verified"]),
        "model_version": row["model_version"],
        "elapsed_ms": row["elapsed_ms"],
        "created_at": row["created_at"],
    }


def list_scans(db_path: str, key_id: str, limit: int = 50, offset: int = 0):
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM scans WHERE key_id = ?"
            " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
            (key_id, int(limit), int(offset)),
        ).fetchall()
    return [_row_to_scan(r) for r in rows]


def count_scans(db_path: str, key_id: str) -> int:
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM scans WHERE key_id = ?", (key_id,)
        ).fetchone()
    return row["n"]


def get_scan(db_path: str, key_id: str, scan_id: str):
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE id = ? AND key_id = ?", (scan_id, key_id)
        ).fetchone()
    return _row_to_scan(row) if row else None
```

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `python -m pytest tests/test_store.py -v`
Expected: 13 passed.

- [ ] **Step 5: Commit**

```bash
git add api/store.py tests/test_store.py
git commit -m "feat(api): add SQLite storage for keys and scan history

Keys are stored only as SHA-256; the plaintext is shown once at creation
and is unrecoverable after that.

Raw HTML is not persisted unless STORE_RAW_HTML is on. It is
attacker-controlled content and keeping it by default is a liability —
but retention is exactly what data collection for retraining needs, so
it stays available behind a flag.

History is scoped by key: one caller cannot read another's scans."
```

---

### Task 5: Authentication and rate limiting

**Files:**
- Create: `api/auth.py`
- Create: `tests/test_auth.py`

**Interfaces:**
- Consumes: `api.store`, `api.config.Settings`.
- Produces:
  - `api.auth.AuthError(Exception)` with `code`, `status`, and optional `retry_after: int`.
  - `api.auth.authenticate(db_path: str, header: str | None) -> sqlite3.Row` — raises `AuthError`.
  - `api.auth.check_rate_limit(db_path: str, key_id: str, limit: int) -> None` — raises `AuthError` when over.
  - `api.auth.require_key` — a FastAPI dependency returning the key row.

- [ ] **Step 1: Write the failing test**

Create `tests/test_auth.py`:

```python
import pytest

from api import store
from api.auth import AuthError, authenticate, check_rate_limit


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "auth.db")
    store.init_db(path)
    return path


def test_missing_header_is_rejected(db):
    with pytest.raises(AuthError) as exc:
        authenticate(db, None)
    assert exc.value.status == 401


@pytest.mark.parametrize(
    "header", ["", "sk_live_abc", "Basic abc", "Bearer", "Bearer  "]
)
def test_malformed_header_is_rejected(db, header):
    with pytest.raises(AuthError):
        authenticate(db, header)


def test_unknown_key_is_rejected(db):
    with pytest.raises(AuthError):
        authenticate(db, "Bearer sk_live_doesnotexist")


def test_valid_key_authenticates(db):
    key_id, plaintext = store.create_key(db, "sam")
    row = authenticate(db, f"Bearer {plaintext}")
    assert row["id"] == key_id


def test_revoked_key_is_rejected(db):
    key_id, plaintext = store.create_key(db, "sam")
    store.revoke_key(db, key_id)
    with pytest.raises(AuthError):
        authenticate(db, f"Bearer {plaintext}")


def test_rate_limit_allows_up_to_the_cap(db):
    key_id, _ = store.create_key(db, "sam", rate_limit=3)
    for _ in range(3):
        check_rate_limit(db, key_id, 3)


def test_rate_limit_rejects_past_the_cap(db):
    key_id, _ = store.create_key(db, "sam", rate_limit=2)
    check_rate_limit(db, key_id, 2)
    check_rate_limit(db, key_id, 2)

    with pytest.raises(AuthError) as exc:
        check_rate_limit(db, key_id, 2)

    assert exc.value.status == 429
    assert exc.value.retry_after > 0
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `python -m pytest tests/test_auth.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'api.auth'`.

- [ ] **Step 3: Write `api/auth.py`**

```python
"""API key authentication and per-key rate limiting.

Rate limiting is a fixed window counted in SQLite. Two users do not
justify a Redis dependency, and counting in the database means the limit
survives a restart.
"""

from datetime import datetime, timezone

from fastapi import Depends, Header

from api import store
from api.config import Settings, get_settings


class AuthError(Exception):
    def __init__(self, message: str, code: str, status: int, retry_after: int = 0):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status
        self.retry_after = retry_after


def _bearer_token(header):
    if not header:
        return None
    parts = header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1].strip()
    return token or None


def authenticate(db_path: str, header):
    token = _bearer_token(header)
    if not token:
        raise AuthError(
            "Provide your key as: Authorization: Bearer sk_live_...",
            "unauthorized",
            401,
        )

    row = store.find_key_by_hash(db_path, store.hash_key(token))
    if row is None or row["revoked_at"] is not None:
        raise AuthError("Unknown or revoked API key.", "unauthorized", 401)

    return row


def check_rate_limit(db_path: str, key_id: str, limit: int) -> None:
    now = datetime.now(timezone.utc)
    window = now.strftime("%Y-%m-%dT%H:%M")

    with store.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO rate_windows (key_id, window_start, count) VALUES (?, ?, 1)"
            " ON CONFLICT(key_id, window_start) DO UPDATE SET count = count + 1",
            (key_id, window),
        )
        row = conn.execute(
            "SELECT count FROM rate_windows WHERE key_id = ? AND window_start = ?",
            (key_id, window),
        ).fetchone()

        # Keep the table from growing without bound.
        conn.execute(
            "DELETE FROM rate_windows WHERE window_start < ?", (window,)
        )

    if row["count"] > limit:
        raise AuthError(
            f"Rate limit of {limit} requests per minute exceeded.",
            "rate_limited",
            429,
            retry_after=60 - now.second,
        )


def require_key(
    authorization: str = Header(default=None),
    settings: Settings = Depends(get_settings),
):
    """FastAPI dependency: authenticate, rate limit, record use."""
    row = authenticate(settings.db_path, authorization)
    check_rate_limit(settings.db_path, row["id"], row["rate_limit"])
    store.touch_key(settings.db_path, row["id"])
    return row
```

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `python -m pytest tests/test_auth.py -v`
Expected: 11 passed.

- [ ] **Step 5: Commit**

```bash
git add api/auth.py tests/test_auth.py
git commit -m "feat(api): add key authentication and per-key rate limiting

Fixed-window counting in SQLite rather than Redis — two users do not
justify another service, and counting in the database means the limit
survives a restart. Old windows are swept on write so the table cannot
grow without bound."
```

---

### Task 6: Application factory, schemas, and `POST /v1/scan` for HTML

The first working endpoint. HTML input only — no network involved, so it can be tested without touching `fetching.py`.

**Files:**
- Create: `api/schemas.py`
- Create: `api/service.py`
- Create: `api/routers/__init__.py`
- Create: `api/routers/scan.py`
- Create: `api/main.py` (the file exists and is empty)
- Create: `tests/conftest.py`
- Create: `tests/test_scan_html.py`

**Interfaces:**
- Consumes: `api.scoring`, `api.store`, `api.auth`, `api.fetching`, `api.config`.
- Produces:
  - `api.schemas.ScanRequest` — Pydantic model, fields `url: str | None`, `html: str | None`, `threshold: float | None`.
  - `api.schemas.ScanResponse` — the response body from spec §4.2.
  - `api.service.resolve_threshold(requested, key_row, settings) -> float` — request, then key default, then global default.
  - `api.service.run_scan(bundle, settings, key_id: str, threshold_default: float, *, html=None, url=None, source: str, target: str, requested_threshold=None) -> dict` — scores, persists, and returns the response dict (without `key_id`, `content_sha256`, or `raw_html`).
  - `api.main.create_app() -> FastAPI`.
  - `api.main.app` — the module-level ASGI application.

- [ ] **Step 1: Write the failing test**

Create `tests/conftest.py`:

```python
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
```

Create `tests/test_scan_html.py`:

```python
from tests.conftest import read_fixture


def test_scan_html_returns_a_full_verdict(client):
    response = client.post(
        "/v1/scan",
        json={"html": read_fixture("phishy.html")},
        headers=client.auth_headers,
    )

    assert response.status_code == 200
    body = response.json()

    assert body["id"].startswith("scn_")
    assert body["source"] == "html"
    assert 0.0 <= body["score"] <= 1.0
    assert body["verdict"] in ("phishing", "benign")
    assert body["threshold"] == 0.30
    assert len(body["features"]) == 13
    assert body["tls_verified"] is None
    assert body["elapsed_ms"] >= 0
    assert body["created_at"].endswith("Z")


def test_features_are_always_returned(client):
    """A bare score is not auditable. A practitioner needs the evidence."""
    from extract_features import FEATURE_ORDER

    response = client.post(
        "/v1/scan",
        json={"html": "<html><body><form></form></body></html>"},
        headers=client.auth_headers,
    )

    assert set(response.json()["features"]) == set(FEATURE_ORDER)


def test_bakery_page_is_flagged_with_the_bias_warning(client):
    response = client.post(
        "/v1/scan",
        json={"html": read_fixture("realistic_benign.html")},
        headers=client.auth_headers,
    )
    body = response.json()

    assert body["verdict"] == "phishing"
    assert "small_simple_site" in body["warnings"]


def test_raising_the_threshold_changes_the_verdict(client):
    html = read_fixture("realistic_benign.html")

    low = client.post(
        "/v1/scan", json={"html": html, "threshold": 0.30}, headers=client.auth_headers
    ).json()
    high = client.post(
        "/v1/scan", json={"html": html, "threshold": 0.95}, headers=client.auth_headers
    ).json()

    assert low["verdict"] == "phishing"
    assert high["verdict"] == "benign"
    assert high["threshold"] == 0.95


def test_page_url_alongside_html_does_not_fetch(client):
    """Supplying both is valid: the URL only classifies links."""
    response = client.post(
        "/v1/scan",
        json={
            "html": '<html><a href="https://example.com/x">y</a></html>',
            "url": "https://example.com/",
        },
        headers=client.auth_headers,
    )

    body = response.json()
    assert body["source"] == "html"
    assert body["features"]["internal_link_count"] == 1


def test_neither_url_nor_html_is_a_422(client):
    response = client.post("/v1/scan", json={}, headers=client.auth_headers)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_threshold_out_of_range_is_a_422(client):
    response = client.post(
        "/v1/scan",
        json={"html": "<html></html>", "threshold": 1.5},
        headers=client.auth_headers,
    )
    assert response.status_code == 422


def test_oversized_html_is_a_413(client):
    response = client.post(
        "/v1/scan",
        json={"html": "x" * (5 * 1024 * 1024 + 1)},
        headers=client.auth_headers,
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "payload_too_large"


def test_missing_key_is_a_401(client):
    response = client.post("/v1/scan", json={"html": "<html></html>"})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"


def test_bad_key_is_a_401(client):
    response = client.post(
        "/v1/scan",
        json={"html": "<html></html>"},
        headers={"Authorization": "Bearer sk_live_wrong"},
    )
    assert response.status_code == 401


def test_rate_limit_returns_429_with_retry_after(client):
    from api import store
    from api.config import get_settings

    key_id, plaintext = store.create_key(
        get_settings().db_path, "tiny", rate_limit=2
    )
    headers = {"Authorization": f"Bearer {plaintext}"}

    for _ in range(2):
        assert client.post(
            "/v1/scan", json={"html": "<html></html>"}, headers=headers
        ).status_code == 200

    response = client.post(
        "/v1/scan", json={"html": "<html></html>"}, headers=headers
    )
    assert response.status_code == 429
    assert response.json()["error"]["code"] == "rate_limited"
    assert int(response.headers["Retry-After"]) > 0
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `python -m pytest tests/test_scan_html.py -v`
Expected: FAIL — `ImportError: cannot import name 'create_app' from 'api.main'`.

- [ ] **Step 3: Write `api/schemas.py`**

```python
"""Request and response models."""

from typing import Optional

from pydantic import BaseModel, Field, model_validator

MAX_HTML_BYTES = 5 * 1024 * 1024


class ScanRequest(BaseModel):
    url: Optional[str] = Field(default=None, max_length=2048)
    html: Optional[str] = None
    threshold: Optional[float] = Field(default=None, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def require_one_input(self):
        if not self.url and not self.html:
            raise ValueError("Provide either 'url' or 'html'.")
        return self


class ErrorBody(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorBody


class ScanResponse(BaseModel):
    id: str
    target: str
    source: str
    score: float
    verdict: str
    threshold: float
    features: dict
    warnings: list
    tls_verified: Optional[bool] = None
    model_version: str
    elapsed_ms: int
    created_at: str


class ScanListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    scans: list
```

- [ ] **Step 4: Write `api/service.py`**

```python
"""The scan pipeline, shared by the JSON API and the dashboard.

Both front doors call run_scan, so they cannot give different answers to
the same page.
"""

import hashlib
import time

from api import scoring, store
from api.fetching import fetch


def resolve_threshold(requested, key_row, settings) -> float:
    """Request, then key default, then global default."""
    if requested is not None:
        return float(requested)
    if key_row is not None and key_row["threshold"] is not None:
        return float(key_row["threshold"])
    return float(settings.default_threshold)


def run_scan(
    bundle,
    settings,
    key_id: str,
    threshold_default,
    *,
    html=None,
    url=None,
    source: str,
    target: str,
    requested_threshold=None,
):
    """Score a page, persist the result, return the response dict."""
    started = time.perf_counter()

    tls_verified = None
    truncated = False
    page_url = url

    if html is None:
        result = fetch(url, settings)
        html = result.html
        page_url = result.final_url
        target = result.final_url
        tls_verified = result.tls_verified
        truncated = result.truncated

    score, features = scoring.score_html(bundle, html, page_url=page_url)

    threshold = (
        float(requested_threshold)
        if requested_threshold is not None
        else float(threshold_default)
    )
    verdict = scoring.verdict_for(score, threshold)
    warnings = scoring.build_warnings(
        features, verdict, settings.small_site_tag_threshold
    )

    if tls_verified is False:
        warnings.append("tls_verification_failed")
    if truncated:
        warnings.append("truncated")

    record = {
        "id": store.new_id("scn"),
        "key_id": key_id,
        "source": source,
        "target": target,
        "content_sha256": hashlib.sha256(html.encode("utf-8", "replace")).hexdigest(),
        "score": round(score, 4),
        "verdict": verdict,
        "threshold": threshold,
        "features": features,
        "warnings": warnings,
        "tls_verified": tls_verified,
        "model_version": bundle.version,
        "elapsed_ms": int((time.perf_counter() - started) * 1000),
        "created_at": store.utcnow(),
        "raw_html": html,
    }

    store.save_scan(settings.db_path, record, store_raw_html=settings.store_raw_html)

    response = dict(record)
    response.pop("raw_html")
    response.pop("key_id")
    response.pop("content_sha256")
    return response
```

- [ ] **Step 5: Write `api/routers/scan.py`**

This imports `ApiError` from `api/errors.py`, which is written in Step 6 — read both steps before starting, and expect an import error until Step 6 is done.

Create `api/routers/__init__.py` as an empty file, then:

```python
"""POST /v1/scan"""

from fastapi import APIRouter, Depends, Request

from api.auth import require_key
from api.config import Settings, get_settings
from api.schemas import MAX_HTML_BYTES, ScanRequest, ScanResponse
from api.service import resolve_threshold, run_scan
from api.errors import ApiError

router = APIRouter(prefix="/v1", tags=["scan"])


@router.post("/scan", response_model=ScanResponse)
def scan(
    body: ScanRequest,
    request: Request,
    key_row=Depends(require_key),
    settings: Settings = Depends(get_settings),
):
    if body.html is not None and len(body.html.encode("utf-8")) > MAX_HTML_BYTES:
        raise ApiError("HTML body exceeds 5 MB.", "payload_too_large", 413)

    source = "html" if body.html is not None else "url"
    target = body.url if body.url else "(pasted html)"

    return run_scan(
        request.app.state.bundle,
        settings,
        key_id=key_row["id"],
        threshold_default=resolve_threshold(None, key_row, settings),
        html=body.html,
        url=body.url,
        source=source,
        target=target,
        requested_threshold=body.threshold,
    )
```

- [ ] **Step 6: Write `api/errors.py`**

```python
"""One error shape for the whole API."""

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from api.auth import AuthError
from api.fetching import FetchError


class ApiError(Exception):
    def __init__(self, message: str, code: str, status: int):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status


def _body(code: str, message: str):
    return {"error": {"code": code, "message": message}}


def register_error_handlers(app):
    @app.exception_handler(ApiError)
    def handle_api_error(request: Request, exc: ApiError):
        return JSONResponse(
            status_code=exc.status, content=_body(exc.code, exc.message)
        )

    @app.exception_handler(AuthError)
    def handle_auth_error(request: Request, exc: AuthError):
        headers = {"Retry-After": str(exc.retry_after)} if exc.retry_after else None
        return JSONResponse(
            status_code=exc.status,
            content=_body(exc.code, exc.message),
            headers=headers,
        )

    @app.exception_handler(FetchError)
    def handle_fetch_error(request: Request, exc: FetchError):
        return JSONResponse(
            status_code=exc.status, content=_body(exc.code, str(exc))
        )

    @app.exception_handler(RequestValidationError)
    def handle_validation_error(request: Request, exc: RequestValidationError):
        first = exc.errors()[0] if exc.errors() else {}
        message = first.get("msg", "Request body failed validation.")
        return JSONResponse(
            status_code=422, content=_body("validation_error", message)
        )
```

- [ ] **Step 7: Write `api/main.py`**

```python
"""FastAPI application.

The model bundle is loaded once at startup and held on app.state.
joblib.load on a 23 MB bundle is far too slow to repeat per request.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from api import store
from api.config import get_settings
from api.errors import register_error_handlers
from api.routers import scan as scan_router
from api.scoring import load_bundle


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    store.init_db(settings.db_path)
    store.ensure_internal_key(settings.db_path, settings.default_threshold)
    # Raises on feature mismatch, which stops the app rather than
    # letting it serve meaningless predictions.
    app.state.bundle = load_bundle(settings.model_path)
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="Phishing Detector API",
        version="1.0.0",
        description=(
            "Static HTML phishing detection. Pages are downloaded but never "
            "rendered or executed."
        ),
        lifespan=lifespan,
    )
    register_error_handlers(app)
    app.include_router(scan_router.router)
    return app


app = create_app()
```

- [ ] **Step 8: Run the tests and make sure they pass**

Run: `python -m pytest tests/test_scan_html.py -v`
Expected: 11 passed.

- [ ] **Step 9: Commit**

```bash
git add api/schemas.py api/service.py api/errors.py api/routers/ api/main.py tests/conftest.py tests/test_scan_html.py
git commit -m "feat(api): add app factory and POST /v1/scan for HTML input

The model loads once at startup and lives on app.state; loading a 23 MB
bundle per request would be unusable.

run_scan is shared by the JSON API and the dashboard so the two front
doors cannot drift into giving different answers for the same page.

Threshold precedence is request, then key default, then global default,
and the value applied is echoed in the response."
```

---

### Task 7: URL scanning and file upload

**Files:**
- Modify: `api/routers/scan.py`
- Create: `tests/test_scan_url.py`
- Create: `tests/test_scan_file.py`

**Interfaces:**
- Consumes: everything from Task 6, plus `api.fetching.fetch`.
- Produces: `POST /v1/scan/file` accepting multipart field `file`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_scan_url.py`:

```python
import pytest

from tests.conftest import read_fixture


@pytest.fixture
def fake_fetch(monkeypatch):
    """Substitute the network. fetching.py has its own tests."""
    import api.service as service
    from api.fetching import FetchResult

    def _fetch(url, settings):
        return FetchResult(
            html=read_fixture("phishy.html"),
            final_url="https://phish.test/login",
            tls_verified=False,
            truncated=False,
        )

    monkeypatch.setattr(service, "fetch", _fetch)


def test_scan_url_reports_the_final_url_and_tls_state(client, fake_fetch):
    response = client.post(
        "/v1/scan",
        json={"url": "https://phish.test/login"},
        headers=client.auth_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["source"] == "url"
    assert body["target"] == "https://phish.test/login"
    assert body["tls_verified"] is False
    assert "tls_verification_failed" in body["warnings"]


def test_blocked_url_is_a_403(client):
    response = client.post(
        "/v1/scan",
        json={"url": "http://169.254.169.254/latest/meta-data/"},
        headers=client.auth_headers,
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "url_blocked"


def test_non_http_scheme_is_a_400(client):
    response = client.post(
        "/v1/scan",
        json={"url": "file:///etc/passwd"},
        headers=client.auth_headers,
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_url"


def test_truncated_body_warns(client, monkeypatch):
    import api.service as service
    from api.fetching import FetchResult

    monkeypatch.setattr(
        service,
        "fetch",
        lambda url, settings: FetchResult(
            html="<html></html>",
            final_url="https://big.test/",
            tls_verified=True,
            truncated=True,
        ),
    )

    response = client.post(
        "/v1/scan", json={"url": "https://big.test/"}, headers=client.auth_headers
    )

    assert "truncated" in response.json()["warnings"]
```

Create `tests/test_scan_file.py`:

```python
def test_upload_an_html_file(client):
    with open("data/phishy.html", "rb") as fh:
        response = client.post(
            "/v1/scan/file",
            files={"file": ("phishy.html", fh, "text/html")},
            headers=client.auth_headers,
        )

    assert response.status_code == 200
    body = response.json()
    assert body["source"] == "file"
    assert body["target"] == "phishy.html"
    assert len(body["features"]) == 13


def test_non_html_extension_is_rejected(client):
    response = client.post(
        "/v1/scan/file",
        files={"file": ("payload.exe", b"MZ\x90\x00", "application/octet-stream")},
        headers=client.auth_headers,
    )

    assert response.status_code == 415
    assert response.json()["error"]["code"] == "unsupported_content_type"


def test_oversized_upload_is_a_413(client):
    big = b"<html>" + b"x" * (5 * 1024 * 1024) + b"</html>"
    response = client.post(
        "/v1/scan/file",
        files={"file": ("big.html", big, "text/html")},
        headers=client.auth_headers,
    )

    assert response.status_code == 413


def test_upload_requires_a_key(client):
    response = client.post(
        "/v1/scan/file", files={"file": ("x.html", b"<html></html>", "text/html")}
    )
    assert response.status_code == 401
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `python -m pytest tests/test_scan_url.py tests/test_scan_file.py -v`

Expected: all 4 tests in `test_scan_file.py` FAIL with 404 — the route does not exist yet. All 4 in `test_scan_url.py` **pass already**, because `run_scan` from Task 6 fetches whenever `html` is absent. They are added here to lock that behaviour down before the file endpoint is layered on; if any of them fails, something in Task 6 regressed and that comes first.

- [ ] **Step 3: Append the file endpoint to `api/routers/scan.py`**

Add these imports at the top of the existing file:

```python
from fastapi import File, UploadFile
```

Then append:

```python
ALLOWED_UPLOAD_SUFFIXES = (".html", ".htm")


@router.post("/scan/file", response_model=ScanResponse)
async def scan_file(
    request: Request,
    file: UploadFile = File(...),
    threshold: float = None,
    key_row=Depends(require_key),
    settings: Settings = Depends(get_settings),
):
    name = (file.filename or "upload").strip()

    if not name.lower().endswith(ALLOWED_UPLOAD_SUFFIXES):
        raise ApiError(
            "Only .html and .htm files can be scanned.",
            "unsupported_content_type",
            415,
        )

    raw = await file.read(MAX_HTML_BYTES + 1)
    if len(raw) > MAX_HTML_BYTES:
        raise ApiError("Uploaded file exceeds 5 MB.", "payload_too_large", 413)

    if threshold is not None and not 0.0 <= threshold <= 1.0:
        raise ApiError("threshold must be between 0 and 1.", "validation_error", 422)

    return run_scan(
        request.app.state.bundle,
        settings,
        key_id=key_row["id"],
        threshold_default=resolve_threshold(None, key_row, settings),
        html=raw.decode("utf-8", errors="replace"),
        url=None,
        source="file",
        target=name,
        requested_threshold=threshold,
    )
```

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `python -m pytest tests/test_scan_url.py tests/test_scan_file.py -v`
Expected: 8 passed.

- [ ] **Step 5: Commit**

```bash
git add api/routers/scan.py tests/test_scan_url.py tests/test_scan_file.py
git commit -m "feat(api): scan by URL and by uploaded file

URL scans report the final URL after redirects, not the submitted one,
and surface whether the certificate validated. Blocked and malformed
URLs map to 403 and 400 rather than a generic failure, so a caller can
tell 'we refused this' from 'we could not reach it'."
```

---

### Task 8: History and metadata endpoints

**Files:**
- Create: `api/routers/scans.py`
- Create: `api/routers/meta.py`
- Modify: `api/main.py`
- Create: `tests/test_history.py`
- Create: `tests/test_meta.py`

**Interfaces:**
- Consumes: `api.store.list_scans`, `api.store.get_scan`, `api.store.count_scans`.
- Produces: `GET /v1/scans`, `GET /v1/scans/{scan_id}`, `GET /v1/model`, `GET /v1/health`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_history.py`:

```python
def scan_once(client, html="<html><body></body></html>"):
    return client.post(
        "/v1/scan", json={"html": html}, headers=client.auth_headers
    ).json()


def test_history_lists_newest_first(client):
    first = scan_once(client)
    second = scan_once(client)

    body = client.get("/v1/scans", headers=client.auth_headers).json()

    assert body["total"] == 2
    assert [s["id"] for s in body["scans"]] == [second["id"], first["id"]]


def test_history_paginates(client):
    for _ in range(3):
        scan_once(client)

    body = client.get("/v1/scans?limit=2&offset=0", headers=client.auth_headers).json()

    assert len(body["scans"]) == 2
    assert body["limit"] == 2
    assert body["offset"] == 0
    assert body["total"] == 3


def test_single_scan_includes_features(client):
    created = scan_once(client)

    body = client.get(f"/v1/scans/{created['id']}", headers=client.auth_headers).json()

    assert body["id"] == created["id"]
    assert len(body["features"]) == 13


def test_unknown_scan_is_a_404(client):
    response = client.get("/v1/scans/scn_nope", headers=client.auth_headers)
    assert response.status_code == 404


def test_another_keys_scan_is_not_visible(client):
    from api import store
    from api.config import get_settings

    created = scan_once(client)
    _, other = store.create_key(get_settings().db_path, "other")

    response = client.get(
        f"/v1/scans/{created['id']}", headers={"Authorization": f"Bearer {other}"}
    )
    assert response.status_code == 404


def test_history_requires_a_key(client):
    assert client.get("/v1/scans").status_code == 401
```

Create `tests/test_meta.py`:

```python
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
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `python -m pytest tests/test_history.py tests/test_meta.py -v`
Expected: FAIL — 404 on every new route.

- [ ] **Step 3: Write `api/routers/scans.py`**

```python
"""GET /v1/scans and GET /v1/scans/{id}"""

from fastapi import APIRouter, Depends, Query

from api import store
from api.auth import require_key
from api.config import Settings, get_settings
from api.errors import ApiError
from api.schemas import ScanListResponse

router = APIRouter(prefix="/v1", tags=["history"])


@router.get("/scans", response_model=ScanListResponse)
def list_scans(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    key_row=Depends(require_key),
    settings: Settings = Depends(get_settings),
):
    return {
        "total": store.count_scans(settings.db_path, key_row["id"]),
        "limit": limit,
        "offset": offset,
        "scans": store.list_scans(settings.db_path, key_row["id"], limit, offset),
    }


@router.get("/scans/{scan_id}")
def get_scan(
    scan_id: str,
    key_row=Depends(require_key),
    settings: Settings = Depends(get_settings),
):
    record = store.get_scan(settings.db_path, key_row["id"], scan_id)
    if record is None:
        raise ApiError("No such scan.", "not_found", 404)
    return record
```

- [ ] **Step 4: Write `api/routers/meta.py`**

```python
"""GET /v1/model and GET /v1/health"""

import json
import os

from fastapi import APIRouter, Depends, Request

from api.auth import require_key
from api.config import Settings, get_settings

router = APIRouter(prefix="/v1", tags=["meta"])

LICENCE = (
    "Model trained on CIC-Trap4Phish, CC BY-NC 4.0 — non-commercial use only. "
    "Cite Nejati et al. (2026), arXiv:2602.09015."
)

KNOWN_LIMITATIONS = [
    "Trained on benign pages with a median 514 HTML tags against malicious "
    "pages with 91, so small simple sites are over-flagged. Responses carry "
    "a small_simple_site warning when this applies."
]


@router.get("/health")
def health(request: Request):
    bundle = getattr(request.app.state, "bundle", None)
    return {
        "status": "ok",
        "model_loaded": bundle is not None,
        "model_version": bundle.version if bundle else None,
        "version": "1.0.0",
    }


@router.get("/model")
def model_info(
    request: Request,
    key_row=Depends(require_key),
    settings: Settings = Depends(get_settings),
):
    bundle = request.app.state.bundle

    metrics = {}
    if os.path.exists("model_metrics.json"):
        with open("model_metrics.json", "r", encoding="utf-8") as fh:
            metrics = json.load(fh)

    return {
        "model_version": bundle.version,
        "threshold": bundle.threshold,
        "your_default_threshold": key_row["threshold"],
        "features": bundle.features,
        "metrics": metrics,
        "licence": LICENCE,
        "known_limitations": KNOWN_LIMITATIONS,
    }
```

- [ ] **Step 5: Mount the new routers in `api/main.py`**

Replace the import line and the `include_router` calls:

```python
from api.routers import meta as meta_router
from api.routers import scan as scan_router
from api.routers import scans as scans_router
```

and inside `create_app`:

```python
    app.include_router(scan_router.router)
    app.include_router(scans_router.router)
    app.include_router(meta_router.router)
```

- [ ] **Step 6: Run the tests and make sure they pass**

Run: `python -m pytest tests/test_history.py tests/test_meta.py -v`
Expected: 10 passed.

- [ ] **Step 7: Commit**

```bash
git add api/routers/scans.py api/routers/meta.py api/main.py tests/test_history.py tests/test_meta.py
git commit -m "feat(api): add scan history and model metadata endpoints

/v1/model reports the threshold, the 13 features, the metrics, the
CC BY-NC licence, and the known small-site bias in plain words. A
detector that will not state its own limitations is not worth trusting.

History is scoped by key: another key's scan is a 404, not a 403, so
the endpoint does not confirm the id exists."
```

---

### Task 9: Key management CLI

**Files:**
- Create: `api/keys.py`
- Create: `tests/test_keys_cli.py`

**Interfaces:**
- Consumes: `api.store`, `api.config`.
- Produces: `python -m api.keys create|list|revoke`, and `api.keys.main(argv: list[str]) -> int`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_keys_cli.py`:

```python
import pytest

from api import keys, store


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "cli.db"))
    monkeypatch.setenv("DASHBOARD_PASSWORD", "pw")
    monkeypatch.setenv("SECRET_KEY", "sk")
    from api.config import get_settings

    get_settings.cache_clear()
    yield str(tmp_path / "cli.db")
    get_settings.cache_clear()


def test_create_prints_the_key_once(env, capsys):
    exit_code = keys.main(["create", "--name", "sam"])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "sk_live_" in output
    assert "shown once" in output.lower()


def test_created_key_authenticates(env, capsys):
    keys.main(["create", "--name", "sam"])
    printed = [
        line for line in capsys.readouterr().out.splitlines() if "sk_live_" in line
    ][0]
    plaintext = printed.split()[-1]

    from api.auth import authenticate

    row = authenticate(env, f"Bearer {plaintext}")
    assert row["name"] == "sam"


def test_create_accepts_threshold_and_rate_limit(env, capsys):
    keys.main(
        ["create", "--name", "sam", "--threshold", "0.5", "--rate-limit", "10"]
    )
    rows = store.list_keys(env)
    created = [r for r in rows if r["name"] == "sam"][0]

    assert created["threshold"] == 0.5
    assert created["rate_limit"] == 10


def test_list_shows_created_keys(env, capsys):
    keys.main(["create", "--name", "sam"])
    capsys.readouterr()

    keys.main(["list"])

    assert "sam" in capsys.readouterr().out


def test_revoke_marks_the_key_and_reports(env, capsys):
    keys.main(["create", "--name", "sam"])
    capsys.readouterr()
    key_id = [r for r in store.list_keys(env) if r["name"] == "sam"][0]["id"]

    assert keys.main(["revoke", key_id]) == 0
    assert "revoked" in capsys.readouterr().out.lower()


def test_revoking_an_unknown_key_exits_nonzero(env, capsys):
    assert keys.main(["revoke", "key_nope"]) == 1


def test_invalid_threshold_is_refused(env):
    assert keys.main(["create", "--name", "sam", "--threshold", "3"]) == 1
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `python -m pytest tests/test_keys_cli.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'api.keys'`.

- [ ] **Step 3: Write `api/keys.py`**

```python
"""API key management.

    python -m api.keys create --name "sam"
    python -m api.keys list
    python -m api.keys revoke key_xxx

Deliberately a CLI and not an HTTP endpoint. An admin endpoint would
need an admin credential to protect it, which is a chicken-and-egg not
worth solving for a handful of users.
"""

import argparse
import sys

from api import store
from api.config import get_settings


def _create(settings, args) -> int:
    if args.threshold is not None and not 0.0 <= args.threshold <= 1.0:
        print("threshold must be between 0 and 1.", file=sys.stderr)
        return 1

    store.init_db(settings.db_path)
    key_id, plaintext = store.create_key(
        settings.db_path,
        name=args.name,
        threshold=args.threshold,
        rate_limit=args.rate_limit,
    )

    print(f"Created key {key_id} for {args.name!r}.")
    print("Store it now — it is shown once and cannot be recovered:")
    print(f"  {plaintext}")
    return 0


def _list(settings, args) -> int:
    store.init_db(settings.db_path)
    rows = store.list_keys(settings.db_path)

    if not rows:
        print("No keys yet. Create one with: python -m api.keys create --name NAME")
        return 0

    print(f"{'ID':<32} {'NAME':<16} {'THRESH':>7} {'RATE':>6}  STATUS")
    for row in rows:
        status = "revoked" if row["revoked_at"] else "active"
        print(
            f"{row['id']:<32} {row['name']:<16} {row['threshold']:>7.2f}"
            f" {row['rate_limit']:>6}  {status}"
        )
    return 0


def _revoke(settings, args) -> int:
    store.init_db(settings.db_path)
    if store.revoke_key(settings.db_path, args.key_id):
        print(f"Key {args.key_id} revoked.")
        return 0
    print(f"No active key with id {args.key_id}.", file=sys.stderr)
    return 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m api.keys")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create", help="Create a new API key")
    create.add_argument("--name", required=True)
    create.add_argument("--threshold", type=float, default=None)
    create.add_argument("--rate-limit", type=int, default=60)

    sub.add_parser("list", help="List keys")

    revoke = sub.add_parser("revoke", help="Revoke a key")
    revoke.add_argument("key_id")

    args = parser.parse_args(argv)
    settings = get_settings()

    return {"create": _create, "list": _list, "revoke": _revoke}[args.command](
        settings, args
    )


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `python -m pytest tests/test_keys_cli.py -v`
Expected: 7 passed.

- [ ] **Step 5: Commit**

```bash
git add api/keys.py tests/test_keys_cli.py
git commit -m "feat(api): add key management CLI

A CLI rather than an admin endpoint: protecting an admin endpoint needs
an admin credential, which is a chicken-and-egg not worth solving here.

Each key carries its own threshold and rate limit, so one caller can run
aggressive at 0.30 while another sits at 0.50. The README already treats
that dial as a product feature."
```

---

### Task 10: Dashboard

**Files:**
- Create: `api/sessions.py`
- Create: `api/routers/ui.py`
- Create: `api/templates/base.html`
- Create: `api/templates/login.html`
- Create: `api/templates/scan.html`
- Create: `api/templates/history.html`
- Create: `api/static/style.css`
- Modify: `api/main.py`
- Create: `tests/test_dashboard.py`

**Interfaces:**
- Consumes: `api.service.run_scan`, `api.store`, `api.config`.
- Produces:
  - `api.sessions.sign(value: str, secret: str) -> str` and `api.sessions.verify(token: str, secret: str) -> str | None`.
  - Routes `GET /`, `POST /`, `GET /history`, `GET /scan/{scan_id}`, `GET /login`, `POST /login`, `POST /logout`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_dashboard.py`:

```python
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
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `python -m pytest tests/test_dashboard.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'api.sessions'`.

- [ ] **Step 3: Write `api/sessions.py`**

```python
"""HMAC-signed session cookie.

Hand-rolled rather than pulling in itsdangerous — it is a dozen lines
and the dependency buys nothing else here.
"""

import base64
import hashlib
import hmac

SEPARATOR = "."


def _signature(value: str, secret: str) -> str:
    digest = hmac.new(
        secret.encode("utf-8"), value.encode("utf-8"), hashlib.sha256
    ).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def sign(value: str, secret: str) -> str:
    return f"{value}{SEPARATOR}{_signature(value, secret)}"


def verify(token: str, secret: str):
    if not token or SEPARATOR not in token:
        return None
    value, _, signature = token.rpartition(SEPARATOR)
    if not hmac.compare_digest(signature, _signature(value, secret)):
        return None
    return value
```

- [ ] **Step 4: Write the templates**

`api/templates/base.html`:

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{% block title %}Phishing Detector{% endblock %}</title>
  <link rel="stylesheet" href="/static/style.css">
</head>
<body>
  <header>
    <strong>Phishing Detector</strong>
    {% if signed_in %}
    <nav>
      <a href="/">Scan</a>
      <a href="/history">History</a>
      <form method="post" action="/logout"><button type="submit">Sign out</button></form>
    </nav>
    {% endif %}
  </header>
  <main>{% block content %}{% endblock %}</main>
</body>
</html>
```

`api/templates/login.html`:

```html
{% extends "base.html" %}
{% block content %}
<h1>Sign in</h1>
{% if error %}<p class="error">{{ error }}</p>{% endif %}
<form method="post" action="/login">
  <label for="password">Password</label>
  <input type="password" id="password" name="password" required autofocus>
  <button type="submit">Sign in</button>
</form>
{% endblock %}
```

`api/templates/scan.html`:

```html
{% extends "base.html" %}
{% block content %}
<h1>Scan a page</h1>

{% if error %}<p class="error">{{ error }}</p>{% endif %}

<form method="post" action="/" enctype="multipart/form-data">
  <label for="url">URL</label>
  <input type="url" id="url" name="url" placeholder="https://example.com/login">

  <label for="html">…or paste HTML</label>
  <textarea id="html" name="html" rows="8"></textarea>

  <label for="file">…or upload an .html file</label>
  <input type="file" id="file" name="file" accept=".html,.htm">

  <label for="threshold">Threshold: <output id="thresholdValue">0.30</output></label>
  <input type="range" id="threshold" name="threshold" min="0" max="1"
         step="0.01" value="0.30"
         oninput="document.getElementById('thresholdValue').textContent =
                  parseFloat(this.value).toFixed(2)">

  <button type="submit">Scan</button>
</form>

{% if result %}
<section class="result {{ result.verdict }}">
  <h2>{{ result.verdict|upper }} — {{ '%.3f'|format(result.score) }}</h2>
  <p>{{ result.target }} · threshold {{ '%.2f'|format(result.threshold) }} ·
     {{ result.elapsed_ms }} ms</p>

  {% for code in result.warnings %}
  <p class="warning">
    {% if code == 'small_simple_site' %}
      This page is small and simple. The model was trained on large benign
      sites, so it over-flags small ordinary ones — treat this verdict with
      caution.
    {% elif code == 'no_links_found' %}
      No links were found on this page, so the minimum-link-length feature
      fell back to zero and may not be comparable.
    {% elif code == 'tls_verification_failed' %}
      The site's certificate did not validate. That is itself a warning sign.
    {% elif code == 'truncated' %}
      The page exceeded 5 MB and was cut short, so these measurements are
      based on part of it only.
    {% else %}{{ code }}{% endif %}
  </p>
  {% endfor %}

  <table>
    <tr><th>Feature</th><th>Value</th></tr>
    {% for name, value in result.features.items() %}
    <tr><td>{{ name }}</td><td>{{ value }}</td></tr>
    {% endfor %}
  </table>
</section>
{% endif %}
{% endblock %}
```

`api/templates/history.html`:

```html
{% extends "base.html" %}
{% block content %}
<h1>History</h1>
{% if not scans %}
<p>Nothing scanned yet.</p>
{% else %}
<table>
  <tr><th>When</th><th>Target</th><th>Score</th><th>Verdict</th><th></th></tr>
  {% for scan in scans %}
  <tr>
    <td>{{ scan.created_at }}</td>
    <td>{{ scan.target }}</td>
    <td>{{ '%.3f'|format(scan.score) }}</td>
    <td class="{{ scan.verdict }}">{{ scan.verdict }}</td>
    <td><a href="/scan/{{ scan.id }}">{{ scan.id }}</a></td>
  </tr>
  {% endfor %}
</table>
{% endif %}
{% endblock %}
```

`api/static/style.css`:

```css
:root { --bad: #b3261e; --good: #1b5e20; --line: #d7d7d7; }
* { box-sizing: border-box; }
body { font: 16px/1.5 system-ui, sans-serif; margin: 0; color: #1a1a1a; }
header { display: flex; justify-content: space-between; align-items: center;
         padding: 1rem 1.5rem; border-bottom: 1px solid var(--line); }
header nav { display: flex; gap: 1rem; align-items: center; }
main { max-width: 52rem; margin: 0 auto; padding: 1.5rem; }
label { display: block; margin: 1rem 0 0.25rem; font-weight: 600; }
input, textarea, button { font: inherit; }
input[type=url], input[type=password], textarea { width: 100%; padding: 0.5rem;
  border: 1px solid var(--line); border-radius: 4px; }
button { margin-top: 1rem; padding: 0.5rem 1rem; border-radius: 4px;
  border: 1px solid var(--line); background: #f4f4f4; cursor: pointer; }
table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
th, td { text-align: left; padding: 0.4rem 0.6rem; border-bottom: 1px solid var(--line); }
.result { margin-top: 2rem; padding: 1rem; border: 1px solid var(--line);
  border-radius: 6px; }
.result.phishing h2, td.phishing { color: var(--bad); }
.result.benign h2, td.benign { color: var(--good); }
.warning { background: #fff5d6; border-left: 4px solid #c79100; padding: 0.6rem 0.8rem; }
.error { color: var(--bad); font-weight: 600; }
```

- [ ] **Step 5: Write `api/routers/ui.py`**

```python
"""The dashboard.

Calls run_scan directly rather than making HTTP requests back to this
same app — same code path as the JSON API, no self-call.
"""

import hmac

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from api import store
from api.config import Settings, get_settings
from api.fetching import FetchError
from api.schemas import MAX_HTML_BYTES
from api.sessions import sign, verify
from api.service import run_scan

router = APIRouter(tags=["dashboard"])
templates = Jinja2Templates(directory="api/templates")

COOKIE_NAME = "session"
SESSION_VALUE = "signed-in"


def is_signed_in(request: Request, settings: Settings) -> bool:
    token = request.cookies.get(COOKIE_NAME)
    return bool(token) and verify(token, settings.secret_key) == SESSION_VALUE


def _redirect(target: str) -> RedirectResponse:
    return RedirectResponse(target, status_code=303)


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse(
        request, "login.html", {"signed_in": False, "error": None}
    )


@router.post("/login", response_class=HTMLResponse)
def login(
    request: Request,
    password: str = Form(...),
    settings: Settings = Depends(get_settings),
):
    if not hmac.compare_digest(password, settings.dashboard_password):
        return templates.TemplateResponse(
            request,
            "login.html",
            {"signed_in": False, "error": "Incorrect password."},
            status_code=401,
        )

    response = _redirect("/")
    response.set_cookie(
        COOKIE_NAME,
        sign(SESSION_VALUE, settings.secret_key),
        httponly=True,
        samesite="lax",
        secure=not settings.debug,
    )
    return response


@router.post("/logout")
def logout():
    response = _redirect("/login")
    response.delete_cookie(COOKIE_NAME)
    return response


@router.get("/", response_class=HTMLResponse)
def scan_form(request: Request, settings: Settings = Depends(get_settings)):
    if not is_signed_in(request, settings):
        return _redirect("/login")
    return templates.TemplateResponse(
        request, "scan.html", {"signed_in": True, "result": None, "error": None}
    )


@router.post("/", response_class=HTMLResponse)
async def submit_scan(
    request: Request,
    url: str = Form(default=""),
    html: str = Form(default=""),
    threshold: float = Form(default=0.30),
    file: UploadFile = File(default=None),
    settings: Settings = Depends(get_settings),
):
    if not is_signed_in(request, settings):
        return _redirect("/login")

    context = {"signed_in": True, "result": None, "error": None}

    uploaded = None
    if file is not None and file.filename:
        raw = await file.read(MAX_HTML_BYTES + 1)
        if len(raw) > MAX_HTML_BYTES:
            context["error"] = "That file is larger than 5 MB."
            return templates.TemplateResponse(request, "scan.html", context)
        uploaded = raw.decode("utf-8", errors="replace")

    if uploaded is not None:
        source, target, body = "file", file.filename, uploaded
    elif html.strip():
        source, target, body = "html", "(pasted html)", html
    elif url.strip():
        source, target, body = "url", url.strip(), None
    else:
        context["error"] = "Give a URL, some HTML, or a file."
        return templates.TemplateResponse(request, "scan.html", context)

    try:
        context["result"] = run_scan(
            request.app.state.bundle,
            settings,
            key_id=store.INTERNAL_KEY_ID,
            threshold_default=threshold,
            html=body,
            url=url.strip() or None,
            source=source,
            target=target,
            requested_threshold=threshold,
        )
    except FetchError as exc:
        context["error"] = str(exc)

    return templates.TemplateResponse(request, "scan.html", context)


@router.get("/history", response_class=HTMLResponse)
def history(request: Request, settings: Settings = Depends(get_settings)):
    if not is_signed_in(request, settings):
        return _redirect("/login")
    return templates.TemplateResponse(
        request,
        "history.html",
        {
            "signed_in": True,
            "scans": store.list_scans(settings.db_path, store.INTERNAL_KEY_ID, 100, 0),
        },
    )


@router.get("/scan/{scan_id}", response_class=HTMLResponse)
def scan_detail(
    scan_id: str, request: Request, settings: Settings = Depends(get_settings)
):
    if not is_signed_in(request, settings):
        return _redirect("/login")

    record = store.get_scan(settings.db_path, store.INTERNAL_KEY_ID, scan_id)
    return templates.TemplateResponse(
        request,
        "scan.html",
        {
            "signed_in": True,
            "result": record,
            "error": None if record else "No such scan.",
        },
    )
```

- [ ] **Step 6: Mount the dashboard and static files in `api/main.py`**

Add these imports:

```python
from fastapi.staticfiles import StaticFiles

from api.routers import ui as ui_router
```

and at the end of `create_app`, after the other routers:

```python
    app.include_router(ui_router.router)
    app.mount("/static", StaticFiles(directory="api/static"), name="static")
```

- [ ] **Step 7: Run the tests and make sure they pass**

Run: `python -m pytest tests/test_dashboard.py -v`
Expected: 12 passed.

- [ ] **Step 8: Run the whole suite**

Run: `python -m pytest -v`
Expected: all tests pass, no failures.

- [ ] **Step 9: Commit**

```bash
git add api/sessions.py api/routers/ui.py api/templates/ api/static/ api/main.py tests/test_dashboard.py
git commit -m "feat(api): add the single-user dashboard

Server-rendered Jinja2, no build step. Routes call run_scan directly
rather than making HTTP requests back to this same app, so the UI and
the JSON API cannot give different answers for the same page.

Warnings render as sentences, not codes. 'small_simple_site' means
nothing to a person looking at a result; an explanation of why a small
site gets over-flagged means something."
```

---

### Task 11: Docker, documentation, and manual verification

**Files:**
- Create: `Dockerfile`
- Create: `.dockerignore`
- Modify: `README.md`
- Create: `docs/API.md`

**Interfaces:**
- Consumes: everything above.
- Produces: a runnable container and usage documentation.

- [ ] **Step 1: Write the `Dockerfile`**

```dockerfile
# 3.11 or newer is required: the model bundle is pickled with
# scikit-learn 1.8.0, which publishes no wheels for 3.10.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# lxml needs a compiler on slim images unless a wheel is available.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY extract_features.py scan.py model_metrics.json ./
COPY phishing_html_model.joblib ./
COPY api/ ./api/

RUN useradd --create-home --uid 1000 appuser \
 && mkdir -p /app/data \
 && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD curl -fsS http://localhost:8000/v1/health || exit 1

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

- [ ] **Step 2: Write `.dockerignore`**

```
.git
.gitignore
.venv
__pycache__
*.pyc
tests/
docs/
data/*.csv
data/*.db
raw/
.env
CODE_EXPLAINED.md
```

The image copies only `api/`, the extractor, the model, and `model_metrics.json`. The `data/` directory is created empty and mounted at run time, so the SQLite file lives on the host and survives the container being replaced.

- [ ] **Step 3: Build the image**

```bash
docker build -t phishing-detector-api .
```

Expected: build succeeds. If `lxml` fails to compile, add `build-essential libxml2-dev libxslt1-dev` to the `apt-get install` line.

- [ ] **Step 4: Run the container and verify health**

Generate a secret first and paste it into the command below — command substitution differs between PowerShell and Git Bash, so it is kept out of the line:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Then, substituting that value and running from the project directory:

```bash
docker run --rm -p 8000:8000 -e DASHBOARD_PASSWORD=changeme -e SECRET_KEY=PASTE_SECRET_HERE -v "C:/Users/USER/Desktop/startup/start-up/data:/app/data" phishing-detector-api
```

In another terminal:

```bash
curl -s http://localhost:8000/v1/health
```

Expected: `{"status":"ok","model_loaded":true,...}`.

- [ ] **Step 5: Verify a real scan end to end**

Find the container id, then create a key inside it:

```bash
docker ps --filter ancestor=phishing-detector-api --format "{{.ID}}"
```

```bash
docker exec -it PASTE_CONTAINER_ID python -m api.keys create --name smoke
```

Then, substituting the printed key:

```bash
curl -s -X POST http://localhost:8000/v1/scan -H "Authorization: Bearer sk_live_YOURKEY" -H "Content-Type: application/json" -d "{\"url\":\"https://example.com\"}"
```

Expected: a JSON verdict with 13 features. Confirm `example.com` is **not** flagged; if it is, note the score — that is the small-site bias, and it is the number to watch after retraining.

- [ ] **Step 6: Verify the SSRF guard against a live server**

```bash
curl -s -X POST http://localhost:8000/v1/scan -H "Authorization: Bearer sk_live_YOURKEY" -H "Content-Type: application/json" -d "{\"url\":\"http://169.254.169.254/latest/meta-data/\"}"
```

Expected: HTTP 403 and `{"error":{"code":"url_blocked",...}}`. **If this returns anything else, stop and fix it before the service ever leaves your machine.**

- [ ] **Step 7: Write `docs/API.md`**

````markdown
# Phishing Detector API

Static HTML phishing detection over HTTP. Pages are downloaded but never
rendered or executed.

## Running it

```
python -m pip install -r requirements.txt
copy .env.example .env          # then edit it
python -m api.keys create --name "your-name"
uvicorn api.main:app --reload --port 8000
```

Interactive docs: http://localhost:8000/docs
Dashboard: http://localhost:8000/

## Authentication

All endpoints except `/v1/health` need a key:

```
Authorization: Bearer sk_live_...
```

Keys are stored only as a SHA-256 hash. The plaintext is shown once at
creation and cannot be recovered — create a new one if you lose it.

## Scanning

```
POST /v1/scan
{"url": "https://example.com/login"}
{"html": "<html>...</html>"}
{"html": "<html>...</html>", "url": "https://example.com/"}
{"url": "https://example.com/", "threshold": 0.5}
```

Supply `url` and the server fetches the page. Supply `html` and it does
not. Supplying both scans your HTML and uses the URL only to tell
internal links from external ones.

`POST /v1/scan/file` takes a multipart `.html` upload in a `file` field.

## Reading the response

```json
{
  "id": "scn_...",
  "score": 0.6951,
  "verdict": "phishing",
  "threshold": 0.30,
  "features": { "tag_count": 91, "form_count": 2, "...": "13 in total" },
  "warnings": ["small_simple_site"],
  "tls_verified": false
}
```

All 13 features come back on every scan so you can audit the verdict
rather than take it on faith.

### Warnings

| Code | Meaning |
|---|---|
| `small_simple_site` | Flagged, but the page is small. The model was trained on large benign sites and over-flags small ordinary ones. Treat with caution. |
| `no_links_found` | No links on the page, so `min_link_length` fell back to 0. |
| `tls_verification_failed` | The certificate did not validate — a signal in its own right. |
| `truncated` | Page exceeded 5 MB; features are based on part of it. |

### The threshold is a dial

0.30 catches about 96.7% of phishing and falsely accuses roughly 1 in 8
innocent pages. Raise it to accuse fewer and miss more. Set a per-key
default at creation, or override per request.

## Errors

Every error has the same shape:

```json
{"error": {"code": "url_blocked", "message": "URL resolves to a private address."}}
```

`400 invalid_url` · `401 unauthorized` · `403 url_blocked` ·
`413 payload_too_large` · `415 unsupported_content_type` ·
`422 validation_error` · `429 rate_limited` · `502 fetch_failed` ·
`504 fetch_timeout`

## Limits

60 requests/minute per key by default. 5 MB per page. 10s read timeout,
3 redirects maximum.

URLs resolving to private, loopback, link-local, or reserved addresses
are refused, and every redirect hop is re-checked.

## Licence

The model is trained on CIC-Trap4Phish, **CC BY-NC 4.0 — non-commercial
use only**. This API may not be sold until the model is retrained on
independently collected data. See `README.md`.
````

- [ ] **Step 8: Add a pointer to `README.md`**

Insert immediately after the "What's in this folder?" table:

```markdown
---

## The API

There is now an HTTP service wrapping all of this — see
[`docs/API.md`](docs/API.md).

```
python -m pip install -r requirements.txt
python -m api.keys create --name "you"
uvicorn api.main:app --reload --port 8000
```

Dashboard at http://localhost:8000/, interactive docs at
http://localhost:8000/docs.

**Requires Python 3.11 or newer.** The model bundle is pickled with
scikit-learn 1.8.0, which has no wheels for 3.10; running on 3.10 forces
1.7.2 and warns that predictions may be invalid.
```

- [ ] **Step 9: Run the whole suite one final time**

Run: `python -m pytest -v`
Expected: all pass.

- [ ] **Step 10: Commit**

```bash
git add Dockerfile .dockerignore docs/API.md README.md
git commit -m "feat(api): add Dockerfile and API documentation

Documents the warning codes in plain words, states the CC BY-NC
restriction where a would-be user will actually see it, and records
the Python 3.11 floor and why it exists.

The container runs as a non-root user with the SQLite file on a mounted
volume so history survives replacement."
```

---

## Verification against success criteria

After Task 11, confirm each spec criterion:

1. **URL scan returns verdict, 13 features, warnings** — Task 11 Step 5.
2. **Every SSRF case refused; metadata endpoint never fetched** — `tests/test_fetching.py` plus Task 11 Step 6 against a live server.
3. **Identical scores through `scan.py` and the API** — `test_scoring_matches_scan_py_exactly`.
4. **Bakery page flagged *and* warned** — `test_bakery_page_is_flagged_with_the_bias_warning`.
5. **Key created, used, rate-limited, revoked** — `tests/test_keys_cli.py`, `test_rate_limit_returns_429_with_retry_after`.
6. **Dashboard scans URL, pasted HTML, and file; shows history** — `tests/test_dashboard.py`.
7. **`docker build` and `docker run` work from env vars alone** — Task 11 Steps 3–5.
8. **Swapping `MODEL_PATH` needs no code change** — `MODEL_PATH` is read in `config.py` and used only at `main.py` startup; the feature guard in `load_bundle` rejects an incompatible bundle rather than mis-serving it.

## Not done, deliberately

- **Batch scanning.** Needs a job queue; revisit when there is evidence anyone wants it.
- **DNS-rebinding pinning.** Recorded as a comment in `fetching.py`.
- **Retraining on independently collected data.** The licence blocker. Unchanged by this work, and the reason `MODEL_PATH` is configuration.
