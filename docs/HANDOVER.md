# Phishing Detector API — getting started

You've been given an API key for a static-HTML phishing detector. It downloads
a page and scores it 0–1 from 13 structural features. **It never renders or
executes the page** — no browser, no JS engine. That's deliberate.

## Read this before you trust a verdict

The model is trained on the CIC-Trap4Phish dataset and it **over-flags real
sites at the default threshold of 0.30**. Measured on live pages:

| Site | Score | Verdict @ 0.30 |
|---|---|---|
| example.com | 0.61 | phishing |
| github.com | 0.56 | phishing |
| wikipedia.org | 0.54 | phishing |
| cloudflare.com | 0.18 | benign |

So treat 0.30 as "show me anything remotely suspicious", not as a verdict.
Start around **0.65–0.70** if you want signal instead of noise, and calibrate
against your own corpus. Every response echoes the threshold it applied.

Every response also returns all 13 features, so you can see *why* a page
scored what it did rather than taking the number on faith.

## Authentication

```
Authorization: Bearer sk_live_...
```

Everything except `/v1/health` needs it. Keys are stored only as a SHA-256
hash — if you lose it, it can't be recovered, only replaced.

## The calls you'll actually use

Scan a live URL (the server fetches it):

```bash
curl -X POST http://HOST:PORT/v1/scan \
  -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"url":"https://suspicious.example/login","threshold":0.65}'
```

Scan HTML you already have (no network, no fetch):

```bash
curl -X POST http://HOST:PORT/v1/scan \
  -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"html":"<html>...</html>"}'
```

Scan a saved sample:

```bash
curl -X POST http://HOST:PORT/v1/scan/file \
  -H "Authorization: Bearer $KEY" -F "file=@sample.html;type=text/html"
```

Your history (scoped to your key — you can't see anyone else's):

```bash
curl "http://HOST:PORT/v1/scans?limit=20" -H "Authorization: Bearer $KEY"
```

What the model is and what it admits to:

```bash
curl http://HOST:PORT/v1/model -H "Authorization: Bearer $KEY"
```

Interactive docs are at `/docs`.

## Response

```json
{
  "id": "scn_...",
  "target": "https://suspicious.example/login",
  "source": "url",
  "score": 0.6951,
  "verdict": "phishing",
  "threshold": 0.65,
  "features": { "tag_count": 91, "form_count": 2, "...": "13 total" },
  "warnings": ["small_simple_site"],
  "tls_verified": false
}
```

`target` is the URL **after** redirects, not the one you submitted.

### Warnings

| Code | Meaning |
|---|---|
| `small_simple_site` | Flagged, but the page is small. The model was trained on large benign sites and over-flags small ordinary ones. |
| `no_links_found` | No links on the page, so `min_link_length` fell back to 0. |
| `tls_verification_failed` | The certificate didn't validate — a signal in its own right. |
| `truncated` | Page exceeded 5 MB; features are based on part of it. |

`tls_verified` is `null` when no HTTPS was involved, and `false` if any hop in
a redirect chain failed verification.

## Errors

Always the same shape:

```json
{"error": {"code": "url_blocked", "message": "..."}}
```

`400 invalid_url` · `401 unauthorized` · `403 url_blocked` ·
`413 payload_too_large` · `415 unsupported_content_type` ·
`422 validation_error` · `429 rate_limited` · `502 fetch_failed` ·
`504 fetch_timeout`

`fetch_failed` is common on major sites — plenty of them block a
non-browser user agent. Fall back to pasting the HTML.

## Limits

120 requests/minute on your key. 5 MB per page. 10s read timeout, 3 redirects.

URLs resolving to private, loopback, link-local, or reserved addresses are
refused, and every redirect hop is re-checked — so it won't be talked into
fetching `169.254.169.254` for you.

## Licence

The model is trained on CIC-Trap4Phish, **CC BY-NC 4.0 — non-commercial use
only**. Fine for research and evaluation. Not for a commercial product until
the model is retrained on independently collected data.
