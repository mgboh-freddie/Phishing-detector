# Phishing Detector API — Design

**Date:** 12 August 2026
**Status:** Approved, ready for implementation planning
**Repo:** https://github.com/mgboh-freddie/Phishing-detector.git

---

## 1. Purpose

Turn the working command-line scanner into a service. Two consumers, one API:

1. **Developers** — principally one security-practitioner friend, authenticating with an API key and calling JSON endpoints.
2. **A minimal web dashboard** — single-user, password-protected, for scanning by hand and reviewing history.

The dashboard is a client of the same scanning logic, not a parallel implementation.

### Out of scope for v1

- Batch scanning (`{"urls": [...]}`), job queues, async polling.
- Multi-tenant accounts, billing, self-service key signup.
- Retraining, data collection, or model changes of any kind.
- Public deployment (a Dockerfile is in scope; actually hosting it is not).

## 2. Constraints inherited from the existing project

These come from `README.md` and are design inputs, not problems to solve here.

**Licence.** The model is trained on CIC-Trap4Phish, licensed CC BY-NC 4.0. Non-commercial only. Publishing the source with attribution is permitted; selling access to the service is not. The API is therefore built now and commercialised only after retraining on independently collected data. Design consequence: **the model bundle path is configuration, and swapping the bundle must require no code change.**

**Known bias.** Benign training pages have a median 514 HTML tags; malicious ones 91. The model has partly learned "small and simple means phishing", and mis-flags `data/realistic_benign.html` (an innocent bakery page) at 0.365. Design consequence: **the API surfaces this as an explicit warning rather than returning a confident wrong answer.**

**Safety property.** The extractor downloads pages but never renders or executes them. This is the entire reason the underlying research uses static features. Design consequence: **no headless browser, ever.**

## 3. Architecture

`extract_features.py` is tested, working, and stays untouched. The API wraps it.

```
start-up/
  extract_features.py      unchanged
  scan.py                  unchanged
  phishing_html_model.joblib
  api/
    __init__.py
    main.py                FastAPI app, router mounting, startup model load
    config.py              env-driven settings
    schemas.py             Pydantic v2 request/response models
    scoring.py             bundle load, feature-order guard, predict
    fetching.py            SSRF-hardened URL fetch
    auth.py                API key verification, rate limiting
    store.py               SQLite: keys, scan history
    keys.py                CLI for key creation/revocation (python -m api.keys)
    routers/
      scan.py              POST /v1/scan, POST /v1/scan/file
      scans.py             GET /v1/scans, GET /v1/scans/{id}
      meta.py              GET /v1/model, GET /v1/health
      ui.py                dashboard routes
    templates/             Jinja2: scan form, result, history, login
    static/                one small CSS file, minimal vanilla JS
  tests/
  Dockerfile
  .dockerignore
  .gitignore
  requirements.txt
  .env.example
```

**Stack:** Python 3.11+, FastAPI, uvicorn, Pydantic v2, Jinja2, stdlib `sqlite3`, `requests` (already a dependency), pytest. No Node, no build step, no Redis, no external database.

**Model loading.** The 23 MB bundle is loaded **once** at application startup via FastAPI's lifespan handler and held in memory. Loading per request is unacceptably slow.

**Feature-order guard.** `scoring.py` retains the check from `scan.py:43`: if the bundle's feature list differs from `FEATURE_ORDER`, the application refuses to start. A silent drift between extractor and model produces garbage predictions without raising an error, which is the failure mode that matters most.

## 4. API surface

All JSON endpoints are versioned under `/v1` and require an API key via `Authorization: Bearer sk_live_…`.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/scan` | `{"url": …}` or `{"html": …, "url": …}` → one verdict |
| `POST` | `/v1/scan/file` | multipart `.html`/`.htm` upload → one verdict |
| `GET` | `/v1/scans` | paginated history for the calling key |
| `GET` | `/v1/scans/{id}` | one past scan with its features |
| `GET` | `/v1/model` | threshold, metrics, feature list, dataset, licence |
| `GET` | `/v1/health` | liveness, model loaded, version — **no auth** |
| `GET` | `/docs` | interactive OpenAPI docs, provided by FastAPI |

### 4.1 `POST /v1/scan`

Request — exactly one of `url` or `html` must be present:

```json
{
  "url": "https://example.com/login",
  "html": null,
  "threshold": 0.30
}
```

- `url` — string, `http`/`https` only, max 2048 characters. If `html` is absent, the server fetches it.
- `html` — string, max 5 MB. If present, no network request is made. `url` may still be supplied alongside it, and is then used **only** to classify internal vs external links (`extract_features.extract_features` takes `page_url` for exactly this).
- `threshold` — optional float, 0.0–1.0 inclusive. Overrides the key's default for this request only.

Supplying both `url` and `html` is valid and does not fetch. Supplying neither is a 422.

**Threshold precedence**, highest first: the request's `threshold`, then the calling key's `threshold` column, then `DEFAULT_THRESHOLD`. The value actually applied is echoed in the response.

### 4.2 Response

```json
{
  "id": "scn_01HQ8ZK3M4N5P6Q7R8S9T0",
  "target": "https://example.com/login",
  "source": "url",
  "score": 0.6951,
  "verdict": "phishing",
  "threshold": 0.30,
  "features": {
    "url_punct_char_count": 214,
    "tag_count": 91,
    "whitespace_ratio": 0.31,
    "entropy": 4.82,
    "form_count": 2,
    "embedded_js_count": 3,
    "html_whitespace_ratio": 0.18,
    "script_entropy": 5.11,
    "min_link_length": 1,
    "external_link_count": 12,
    "total_script_characters": 8422,
    "internal_link_count": 3,
    "url_digit_count": 27
  },
  "warnings": ["small_simple_site"],
  "tls_verified": false,
  "model_version": "et-200-v1",
  "elapsed_ms": 412,
  "created_at": "2026-08-12T14:22:31Z"
}
```

- `id` — `scn_` + ULID.
- `source` — `url` | `html` | `file`.
- `verdict` — `phishing` if `score >= threshold`, else `benign`. Lowercase in JSON.
- `features` — **always returned**, all 13, in `FEATURE_ORDER`. A bare score is not auditable; a security practitioner needs to see why.
- `tls_verified` — `null` when `source` is not `url`.
- `model_version` — read from the bundle; falls back to the model file's SHA-256 prefix if the bundle carries no version.

### 4.3 Warnings

`warnings` is a list of machine-readable codes making known model limitations explicit at the point of use.

| Code | Condition | Rationale |
|---|---|---|
| `small_simple_site` | `verdict == "phishing"` and `tag_count < 150` | The documented benign/malicious tag-count split (514 vs 91 median). This is where the model's learned shortcut fires and where false accusations concentrate. |
| `no_links_found` | No URL-bearing attributes on the page, so `min_link_length` fell back to 0 | `min_link_length` is flagged in `html_feature_spec.md` as a likely mismatch against the researchers' definition when a page has no links. |
| `tls_verification_failed` | certificate did not validate | A signal in its own right, not an error to swallow. |
| `truncated` | body hit the 5 MB cap | Features were computed on partial HTML and are unreliable. |

The `small_simple_site` threshold of 150 tags is a starting value chosen to sit between the two medians. It is configurable and expected to be tuned once real false-positive data exists — and to be removed entirely once retraining eliminates the bias.

### 4.4 Errors

Uniform error body:

```json
{ "error": { "code": "url_blocked", "message": "URL resolves to a private address." } }
```

| Status | Code | When |
|---|---|---|
| 400 | `invalid_url` | Unparseable, wrong scheme, over-length |
| 401 | `unauthorized` | Missing, malformed, unknown, or revoked key |
| 403 | `url_blocked` | Resolves to a private/reserved address, or redirect chain does |
| 413 | `payload_too_large` | HTML body or upload over 5 MB |
| 415 | `unsupported_content_type` | Fetched resource is not HTML or text |
| 422 | `validation_error` | Neither `url` nor `html`; threshold out of range |
| 429 | `rate_limited` | Over the key's per-minute limit; includes `Retry-After` |
| 502 | `fetch_failed` | DNS failure, connection refused, non-2xx upstream |
| 504 | `fetch_timeout` | Connect or read timeout exceeded |

## 5. Fetching untrusted URLs

Accepting a URL means an untrusted party chooses what address the server connects to. `fetching.py` is the control point.

1. **Scheme allowlist** — `http` and `https` only.
2. **Strip credentials** — `user:pass@` removed before the request.
3. **Resolve then judge** — resolve the hostname and reject if *any* returned address falls in: loopback, private (`10/8`, `172.16/12`, `192.168/16`), link-local (`169.254/16`, covering the cloud metadata endpoint), CGNAT (`100.64/10`), multicast, reserved, unspecified. IPv6 equivalents included: `::1`, `fc00::/7`, `fe80::/10`, and IPv4-mapped addresses.
4. **Manual redirects** — `allow_redirects=False`, maximum 3 hops, **every hop re-validated through step 3**. A public URL that redirects to `127.0.0.1` is the standard bypass.
5. **Timeouts** — 5s connect, 10s read.
6. **Size cap** — streamed, aborted past 5 MB, `truncated` warning emitted.
7. **Content-Type** — must be `text/html`, `application/xhtml+xml`, or `text/plain`; otherwise 415.
8. **Never rendered or executed.** Response text is parsed by BeautifulSoup only. No headless browser under any circumstance.

**TLS.** Verification is attempted first; on certificate failure the request is retried unverified and `tls_verified: false` is recorded with a `tls_verification_failed` warning. Broken certificates are normal on phishing sites, so strict-only checking would refuse exactly the pages the product exists to examine. This is safe only because downloaded content is never executed — the same reasoning `collect.py` already applies.

**Known residual risk.** Resolve-then-connect leaves a DNS-rebinding window between validation and connection. Closing it requires pinning the connection to the validated IP while preserving SNI and the `Host` header. Deferred to v2 and recorded as a code comment at the check site, not silently omitted.

## 6. Authentication, limits, storage

### Keys

Format `sk_live_` + 32 URL-safe random characters, generated with `secrets.token_urlsafe`. Stored **only** as SHA-256; the plaintext is displayed once at creation and is unrecoverable. Verification hashes the presented key and compares in constant time.

Created via CLI, not an HTTP endpoint — an admin endpoint would itself need an admin credential, which is a chicken-and-egg not worth solving for two users:

```
python -m api.keys create --name "sam"
python -m api.keys list
python -m api.keys revoke <key_id>
```

Each key carries its own default threshold and rate limit, so one caller can run aggressive at 0.30 while the dashboard sits at 0.50. Per `README.md`, an adjustable threshold is a product feature, not a workaround.

### Rate limiting

Fixed-window counter per key per minute, in SQLite. Default 60/minute. Over-limit returns 429 with `Retry-After`. No Redis.

### Schema

```sql
CREATE TABLE api_keys (
  id            TEXT PRIMARY KEY,      -- key_<ulid>
  name          TEXT NOT NULL,
  key_hash      TEXT NOT NULL UNIQUE,  -- sha256 hex
  threshold     REAL NOT NULL DEFAULT 0.30,
  rate_limit    INTEGER NOT NULL DEFAULT 60,
  created_at    TEXT NOT NULL,
  last_used_at  TEXT,
  revoked_at    TEXT
);

CREATE TABLE scans (
  id             TEXT PRIMARY KEY,     -- scn_<ulid>
  key_id         TEXT REFERENCES api_keys(id),
  source         TEXT NOT NULL,        -- url | html | file
  target         TEXT NOT NULL,        -- URL, filename, or "(pasted html)"
  content_sha256 TEXT NOT NULL,
  score          REAL NOT NULL,
  verdict        TEXT NOT NULL,
  threshold      REAL NOT NULL,
  features       TEXT NOT NULL,        -- JSON
  warnings       TEXT NOT NULL,        -- JSON array
  tls_verified   INTEGER,              -- nullable boolean
  model_version  TEXT NOT NULL,
  elapsed_ms     INTEGER NOT NULL,
  created_at     TEXT NOT NULL,
  raw_html       TEXT                  -- NULL unless STORE_RAW_HTML=true
);

CREATE INDEX idx_scans_key_created ON scans(key_id, created_at DESC);
CREATE TABLE rate_windows (key_id TEXT, window_start TEXT, count INTEGER, PRIMARY KEY (key_id, window_start));
```

**Raw HTML is not stored by default.** It is attacker-controlled content and retaining it is a liability. `STORE_RAW_HTML=true` enables retention for deliberate data collection — which directly serves the retraining work the README identifies as the next milestone.

## 7. Dashboard

Server-rendered Jinja2, no frontend build step. Routes call the scanning service functions directly; they do not make HTTP requests back to the app.

| Route | Purpose |
|---|---|
| `GET /` | Scan form — URL field, paste-HTML textarea, file drop, threshold slider |
| `POST /` | Runs the scan, renders the result card |
| `GET /history` | Recent scans, paginated |
| `GET /scan/{id}` | One scan with all 13 features |
| `GET,POST /login` | Password form |
| `POST /logout` | Clears session |

Single user. Password from `DASHBOARD_PASSWORD`, compared in constant time. Signed session cookie via `SECRET_KEY`, `HttpOnly`, `SameSite=Lax`, `Secure` when not in debug mode. The result card shows verdict, score, threshold, all 13 features, and any warnings in plain language — the `small_simple_site` warning renders as a sentence explaining the bias, not a bare code.

Dashboard scans are attributed to a reserved internal key row so history queries need no special case.

## 8. Configuration

All settings come from environment variables, documented in `.env.example`.

| Variable | Default | Purpose |
|---|---|---|
| `MODEL_PATH` | `phishing_html_model.joblib` | Swappable bundle — the licence escape hatch |
| `DB_PATH` | `data/api.db` | SQLite file |
| `DEFAULT_THRESHOLD` | `0.30` | Fallback when a key sets none |
| `MAX_BODY_BYTES` | `5242880` | 5 MB |
| `FETCH_CONNECT_TIMEOUT` | `5` | Seconds |
| `FETCH_READ_TIMEOUT` | `10` | Seconds |
| `MAX_REDIRECTS` | `3` | Hops |
| `SMALL_SITE_TAG_THRESHOLD` | `150` | Fires `small_simple_site` |
| `STORE_RAW_HTML` | `false` | Retention for data collection |
| `DASHBOARD_PASSWORD` | — | Required; app refuses to start without it |
| `SECRET_KEY` | — | Required; session signing |
| `DEBUG` | `false` | Relaxes cookie `Secure` for local HTTP |

## 9. Testing

Fixtures already exist: `data/phishy.html` and `data/realistic_benign.html`.

**Scoring** — both fixtures produce a score in the expected direction; the feature-order guard raises when given a mismatched bundle; the same HTML through `scan.py` and through `scoring.py` yields identical scores. That last one is the regression test that proves the API did not change the product's answers.

**Fetch guard** — a table of inputs that must all be refused: `http://localhost/`, `http://127.0.0.1/`, `http://10.0.0.1/`, `http://169.254.169.254/latest/meta-data/`, `http://[::1]/`, `file:///etc/passwd`, `ftp://example.com`, and a public URL returning a 302 to a private address. The metadata-endpoint case is the one that matters most; it is the difference between a service and an incident.

**API** — 401 on missing/bad/revoked key; 422 for neither `url` nor `html` and for out-of-range threshold; 413 oversized; 415 non-HTML content type; 429 over limit with `Retry-After`; per-request threshold override changes the verdict at a fixed score; history is scoped to the calling key.

**Warnings** — `realistic_benign.html` at threshold 0.30 is flagged *and* carries `small_simple_site`. This is the test that encodes the honesty requirement, and it is expected to be revisited after retraining.

**Dashboard** — unauthenticated routes redirect to login; a scan through the UI persists and appears in history.

## 10. Delivery

**Git.** `C:\Users\USER\Desktop\startup\start-up` is not currently a git repository — `git status` there resolves to a repo rooted at `C:\Users\USER`, the entire home directory. Committing from the folder as-is would sweep in unrelated projects and dotfiles. Work therefore begins with `git init` inside `start-up` plus a `.gitignore` covering `__pycache__/`, `.venv/`, `*.db`, `.env`, `raw/`, and `*.errors.txt`.

The 23 MB model bundle is committed rather than tracked with LFS. It is well under GitHub's 100 MB limit, and a self-contained repository that works on clone beats a lighter one that needs extra tooling.

Pushing to `https://github.com/mgboh-freddie/Phishing-detector.git` happens only on explicit instruction, after confirming whether the repository is public or private.

**Licence when publishing.** CC BY-NC 4.0 permits redistribution with attribution; `README.md` already carries the required citation. Publishing the code is therefore fine while the project stays non-commercial. Selling access remains blocked until retraining on independently collected data.

**Docker.** A Dockerfile on `python:3.11-slim`, non-root user, `HEALTHCHECK` against `/v1/health`, uvicorn entrypoint. `.dockerignore` excludes `data/*.csv`, `raw/`, and `.git`. The SQLite file lives on a mounted volume so history survives container replacement.

## 11. Success criteria

1. `POST /v1/scan` with a URL returns a verdict, all 13 features, and a warning list.
2. Every SSRF test case is refused; the cloud metadata endpoint is never fetched.
3. Identical HTML scores identically through `scan.py` and through the API.
4. `realistic_benign.html` is flagged **and** carries `small_simple_site` — the bias is visible, not hidden.
5. A named API key can be created, used, rate-limited, and revoked from the CLI.
6. The dashboard scans a URL, a pasted page, and an uploaded file, and shows history.
7. `docker build` and `docker run` produce a working service with only env vars supplied.
8. Replacing `MODEL_PATH` with a retrained bundle of the same 13 features requires no code change.

## 12. References

- `README.md` — project state, licence, known bias
- `html_feature_spec.md` — the 13 feature definitions and their three likely mismatch points
- `model_metrics.json` — threshold 0.30, recall 0.9672, ROC-AUC 0.9845
- Nejati, F., Rabbani, M., Mirani, M., Piya, G., Opushnyev, I., Ghorbani, A. A., & Dadkhah, S. (2026). *CIC-Trap4Phish: A Unified Multi-Format Dataset for Phishing and Quishing Attachment Detection.* arXiv:2602.09015
