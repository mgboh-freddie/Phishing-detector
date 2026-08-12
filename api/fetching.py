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

    try:
        parts = urlsplit(url.strip())
    except ValueError as exc:
        raise InvalidURL(f"URL could not be parsed: {exc}") from exc

    if parts.scheme not in ALLOWED_SCHEMES:
        raise InvalidURL("Only http and https URLs can be scanned.")
    if not parts.hostname:
        raise InvalidURL("URL has no hostname.")

    # Drop any user:password@ before the request is ever made.
    # IPv6 literals lose their brackets in parts.hostname, so they must be
    # re-wrapped here or the rebuilt netloc is corrupted (host truncated,
    # remainder of the address parsed as a bogus port).
    hostname = parts.hostname
    netloc = f"[{hostname}]" if ":" in hostname else hostname
    try:
        port = parts.port
    except ValueError as exc:
        raise InvalidURL(f"URL has an invalid port: {exc}") from exc
    if port:
        netloc = f"{netloc}:{port}"

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


# KNOWN GAP (v2): resolve-then-connect leaves a DNS-rebinding window —
# the hostname can resolve to a public address here and an internal one
# by the time requests opens the socket. Closing it means pinning the
# connection to the validated IP while preserving SNI and the Host
# header, via a custom transport adapter. Recorded rather than hidden.
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

            content_type = (
                response.headers.get("Content-Type", "").split(";")[0].strip().lower()
            )
            if content_type not in ALLOWED_CONTENT_TYPES:
                raise UnsupportedContentType(
                    f"Expected HTML, got {content_type or 'no Content-Type header'}."
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
