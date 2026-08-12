from urllib.parse import urlsplit

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


@pytest.mark.parametrize(
    "url",
    [
        "http://evil.test:99999/x",  # port out of range
        "http://evil.test:abc/x",    # non-numeric port
    ],
)
def test_malformed_port_raises_invalid_url(url):
    """urlsplit(...).port raises ValueError from the stdlib itself on a bad
    port; that must surface as InvalidURL (400), not an uncaught 500."""
    with pytest.raises(InvalidURL):
        validate_url(url)


@pytest.mark.parametrize(
    "url, expected_hostname",
    [
        ("http://[::1]/", "::1"),
        ("http://[2606:4700:4700::1111]/x", "2606:4700:4700::1111"),
        ("https://[2606:4700::1]:8443/y", "2606:4700::1"),
    ],
)
def test_ipv6_literals_keep_their_brackets(url, expected_hostname):
    """parts.hostname strips the brackets from an IPv6 literal; rebuilding
    the netloc without re-adding them corrupts the host (and, with a port
    present, swallows the port into the host too)."""
    cleaned = validate_url(url)
    assert urlsplit(cleaned).hostname == expected_hostname


def _redirect_test_settings():
    from api.config import Settings

    return Settings(
        model_path="x", db_path=":memory:", default_threshold=0.3,
        max_body_bytes=5242880, fetch_connect_timeout=5, fetch_read_timeout=10,
        max_redirects=3, small_site_tag_threshold=400, store_raw_html=False,
        dashboard_password="pw", secret_key="sk", debug=True,
    )


class _FakeOKResponse:
    """A 200 response with a body, for exercising the non-redirect path in
    fetch(), which also calls iter_content and close()."""

    def __init__(self, headers):
        self.status_code = 200
        self.headers = headers
        self.encoding = "utf-8"

    def iter_content(self, chunk_size=65536):
        yield b"<html></html>"

    def close(self):
        pass


def test_missing_content_type_is_rejected(monkeypatch):
    import api.fetching as f

    settings = _redirect_test_settings()
    monkeypatch.setattr(f, "resolve_host", lambda host: ["8.8.8.8"])
    monkeypatch.setattr(
        f, "_request", lambda url, settings, verify: (_FakeOKResponse({}), True)
    )

    with pytest.raises(f.UnsupportedContentType):
        f.fetch("http://public.test/", settings)


def test_content_type_comparison_is_case_insensitive(monkeypatch):
    import api.fetching as f

    settings = _redirect_test_settings()
    monkeypatch.setattr(f, "resolve_host", lambda host: ["8.8.8.8"])
    monkeypatch.setattr(
        f,
        "_request",
        lambda url, settings, verify: (
            _FakeOKResponse({"Content-Type": "Text/HTML"}),
            True,
        ),
    )

    result = f.fetch("http://public.test/", settings)
    assert result.html == "<html></html>"


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
