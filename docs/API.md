# Phishing Detector API

Static HTML phishing detection over HTTP. Pages are downloaded but never
rendered or executed.

## Running it

```
python -m pip install -r requirements.txt
cp .env.example .env            # Windows: copy .env.example .env
python -m api.keys create --name "your-name"
uvicorn api.main:app --reload --port 8000
```

Interactive docs: http://localhost:8000/docs
Dashboard: http://localhost:8000/

Requires Python 3.11 or newer. The model bundle is pickled with
scikit-learn 1.8.0, which publishes no wheels for 3.10.

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/v1/scan` | key | Scan a URL or a block of HTML |
| `POST` | `/v1/scan/file` | key | Scan an uploaded `.html` file |
| `GET` | `/v1/scans` | key | Your scan history, newest first, paginated |
| `GET` | `/v1/scans/{id}` | key | One past scan with its features |
| `GET` | `/v1/model` | key | Threshold, features, metrics, licence, limitations |
| `GET` | `/v1/health` | none | Liveness and whether the model loaded |
| `GET` | `/docs` | none | Interactive OpenAPI docs |

History is scoped to the calling key. Another key's scan is a `404`, not a
`403` — the API will not confirm that an id it cannot show you exists.

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

## Running it in Docker

```
docker build -t phishing-detector-api .
```

```
docker run -p 8000:8000 -e DASHBOARD_PASSWORD=changeme -e SECRET_KEY=your-secret -v phishing-data:/app/data phishing-detector-api
```

**Use a named volume for `/app/data`, as above — not a host bind mount.**
The container runs as a non-root user (uid 1000), and SQLite in WAL mode
has to create `-wal` and `-shm` files *in that directory*, not just write
the database file. A named volume inherits the image's ownership, so this
works. A host directory bind-mounted over `/app/data` keeps the host's own
ownership, and unless that directory is already writable by uid 1000 the
container fails on startup with `unable to open database file`.

If you do need a bind mount, make the host directory writable by uid 1000
first (`chown 1000:1000 ./data`), or run with `--user "$(id -u):$(id -g)"`.

## Licence

The model is trained on CIC-Trap4Phish, **CC BY-NC 4.0 — non-commercial
use only**. This API may not be sold until the model is retrained on
independently collected data. See `README.md`.
