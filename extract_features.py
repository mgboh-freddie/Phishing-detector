"""
HTML feature extractor for the CIC-Trap4Phish 13-feature phishing model.

Computes the 13 features defined in Table X of Nejati et al. (2026),
arXiv:2602.09015, in the exact order the trained model expects.

Usage as a library:
    from extract_features import extract_features
    feats = extract_features(html_string, page_url="https://example.com")

Usage from the command line:
    python extract_features.py page.html
    python extract_features.py folder_of_html/ -o features.csv
"""

import math
import os
import re
import sys
from collections import Counter
from urllib.parse import urlparse

from bs4 import BeautifulSoup

# Order matters — must match the model bundle's feature list.
FEATURE_ORDER = [
    "url_punct_char_count",
    "tag_count",
    "whitespace_ratio",
    "entropy",
    "form_count",
    "embedded_js_count",
    "html_whitespace_ratio",
    "script_entropy",
    "min_link_length",
    "external_link_count",
    "total_script_characters",
    "internal_link_count",
    "url_digit_count",
]

# Punctuation set given explicitly in the paper: / - = ? & : . _
URL_PUNCT = set("/-=?&:._")

# Attributes that can carry a URL. Used for the "all extracted URLs" features.
URL_ATTRS = ("href", "src", "action", "data-url", "formaction")


def shannon_entropy(text):
    """Shannon entropy over characters, in bits. Returns 0.0 for empty input."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def whitespace_proportion(text):
    """Proportion of characters that are whitespace. 0.0 for empty input."""
    if not text:
        return 0.0
    return sum(1 for ch in text if ch.isspace()) / len(text)


def collect_urls(soup):
    """Every URL-bearing attribute value on the page, as raw strings."""
    urls = []
    for tag in soup.find_all(True):
        for attr in URL_ATTRS:
            val = tag.get(attr)
            if isinstance(val, str) and val.strip():
                urls.append(val.strip())
    return urls


NOT_A_LINK = object()  # mailto:, javascript:, tel: — not a navigable target
RELATIVE = object()  # relative path — belongs to the page's own host


def hostname_of(url):
    """
    Classify a href. Returns a hostname string, or one of the two
    sentinels above. Kept separate from the page host so that "relative"
    and "page host unknown" never get confused.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return RELATIVE
    if parsed.scheme and parsed.scheme not in ("http", "https"):
        return NOT_A_LINK
    if parsed.netloc:
        return parsed.netloc.lower()
    return RELATIVE


def extract_features(html, page_url=None):
    """
    Compute the 13 features from an HTML string.

    page_url is optional but strongly recommended: internal vs external link
    classification depends on knowing the page's own hostname. Without it,
    every absolute link counts as external.
    """
    soup = BeautifulSoup(html, "lxml")

    base_host = None
    if page_url:
        base_host = (urlparse(page_url).netloc or "").lower() or None

    # --- Structure ---
    tag_count = len(soup.find_all(True))
    form_count = len(soup.find_all("form"))

    # --- JavaScript ---
    # Inline scripts only: <script> with no src attribute.
    inline_scripts = [s for s in soup.find_all("script") if not s.get("src")]
    embedded_js_count = len(inline_scripts)

    script_bodies = [s.get_text() or "" for s in inline_scripts]
    total_script_characters = sum(len(b) for b in script_bodies)

    # Average entropy ACROSS blocks (not entropy of the concatenation).
    if script_bodies:
        script_entropy = sum(shannon_entropy(b) for b in script_bodies) / len(
            script_bodies
        )
    else:
        script_entropy = 0.0

    # --- Entropy and whitespace ---
    entropy = shannon_entropy(html)
    html_whitespace_ratio = whitespace_proportion(html)
    visible_text = soup.get_text()
    whitespace_ratio = whitespace_proportion(visible_text)

    # --- URLs (all URL-bearing attributes) ---
    all_urls = collect_urls(soup)
    joined = "".join(all_urls)
    url_punct_char_count = sum(1 for ch in joined if ch in URL_PUNCT)
    url_digit_count = sum(1 for ch in joined if ch.isdigit())
    min_link_length = min((len(u) for u in all_urls), default=0)

    # --- Internal vs external, from <a href> only, per the paper ---
    internal_link_count = 0
    external_link_count = 0
    for a in soup.find_all("a"):
        href = a.get("href")
        if not isinstance(href, str) or not href.strip():
            continue
        href = href.strip()
        if href.startswith("#"):
            internal_link_count += 1
            continue
        host = hostname_of(href)
        if host is NOT_A_LINK:
            continue
        if host is RELATIVE:
            # Relative paths always point at the page's own host.
            internal_link_count += 1
        elif base_host is None:
            # Page host unknown, so an absolute link can't be resolved
            # against it. Treated as external.
            external_link_count += 1
        elif host == base_host:
            internal_link_count += 1
        else:
            external_link_count += 1

    return {
        "url_punct_char_count": url_punct_char_count,
        "tag_count": tag_count,
        "whitespace_ratio": whitespace_ratio,
        "entropy": entropy,
        "form_count": form_count,
        "embedded_js_count": embedded_js_count,
        "html_whitespace_ratio": html_whitespace_ratio,
        "script_entropy": script_entropy,
        "min_link_length": min_link_length,
        "external_link_count": external_link_count,
        "total_script_characters": total_script_characters,
        "internal_link_count": internal_link_count,
        "url_digit_count": url_digit_count,
    }


def extract_from_file(path, page_url=None):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return extract_features(fh.read(), page_url=page_url)


def extract_from_url(url, timeout=15):
    """
    Fetch a live page and extract features.

    Requires the `requests` package and network access. Note the safety
    point: this downloads the page but never renders or executes it, which
    is the whole reason the paper uses static features.
    """
    import requests

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
        )
    }
    resp = requests.get(url, timeout=timeout, headers=headers)
    resp.raise_for_status()
    # resp.url, not url — follow redirects to the true final host.
    return extract_features(resp.text, page_url=resp.url)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    target = sys.argv[1]
    out_path = None
    if "-o" in sys.argv:
        out_path = sys.argv[sys.argv.index("-o") + 1]

    rows = []
    if os.path.isdir(target):
        for name in sorted(os.listdir(target)):
            if not name.lower().endswith((".html", ".htm")):
                continue
            feats = extract_from_file(os.path.join(target, name))
            feats["file_name"] = name
            rows.append(feats)
    elif target.startswith(("http://", "https://")):
        feats = extract_from_url(target)
        feats["file_name"] = target
        rows.append(feats)
    else:
        feats = extract_from_file(target)
        feats["file_name"] = os.path.basename(target)
        rows.append(feats)

    if not rows:
        print("No HTML files found.")
        sys.exit(1)

    import pandas as pd

    df = pd.DataFrame(rows)[["file_name"] + FEATURE_ORDER]

    if out_path:
        df.to_csv(out_path, index=False)
        print(f"Wrote {len(df)} row(s) to {out_path}")
    else:
        for col in FEATURE_ORDER:
            print(f"{col:26s} {df.iloc[0][col]}")


if __name__ == "__main__":
    main()
