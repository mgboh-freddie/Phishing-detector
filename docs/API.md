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
