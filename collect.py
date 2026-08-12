"""
Collect your own phishing / benign training data.

Reads a list of URLs, downloads each page safely, runs the feature extractor
over it, and writes a CSV in the same shape as HTML_Top13_Features.csv — so
everything you've already built keeps working.

    py collect.py phish_urls.txt --label 1 --out phish.csv
    py collect.py benign_urls.csv --label 0 --out benign.csv --save-html raw/

Input can be a plain text file (one URL per line) or a CSV with a `url`
column — which is the format PhishTank exports.

Safe to stop and restart. Already-collected URLs are skipped, so if it
crashes or you close the window, just run the same command again.
"""

import argparse
import csv
import os
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from hashlib import sha1
from urllib.parse import urlparse

import pandas as pd
import requests
import urllib3

from extract_features import FEATURE_ORDER, extract_features

# Phishing sites very often have broken or self-signed certificates. We turn
# off verification (see --insecure) and silence the resulting noise. This is
# acceptable ONLY because we never execute what we download.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MAX_BYTES = 3_000_000  # skip anything over ~3 MB; it isn't a normal page
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml",
}


def read_urls(path):
    """Accept a plain .txt of URLs or a .csv with a `url` column."""
    if path.lower().endswith(".csv"):
        df = pd.read_csv(path)
        cols = {c.lower(): c for c in df.columns}
        if "url" not in cols:
            sys.exit(f"{path} has no 'url' column. Columns found: {list(df.columns)}")
        urls = df[cols["url"]].dropna().astype(str).tolist()
    else:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            urls = [line.strip() for line in fh if line.strip()]

    clean, seen = [], set()
    skipped = 0
    for u in urls:
        if not u.startswith(("http://", "https://")):
            u = "http://" + u
        host = urlparse(u).netloc
        # A real hostname has no whitespace and contains a dot. This catches
        # stray text, comments, and header lines in scraped URL lists.
        if not host or " " in host or "." not in host:
            skipped += 1
            continue
        if u not in seen:
            seen.add(u)
            clean.append(u)
    if skipped:
        print(f"Skipped {skipped} line(s) that weren't valid URLs.")
    return clean


def already_done(out_path):
    """URLs present in an existing output file, so reruns don't refetch."""
    if not os.path.exists(out_path):
        return set()
    try:
        df = pd.read_csv(out_path)
        return set(df["file_name"].astype(str))
    except Exception:
        return set()


def fetch(url, timeout, insecure):
    """
    Download a page as text. Never renders, never executes.

    Returns (html, final_url) or raises.
    """
    resp = requests.get(
        url,
        headers=HEADERS,
        timeout=timeout,
        verify=not insecure,
        stream=True,  # so we can check size before pulling it all down
        allow_redirects=True,
    )
    resp.raise_for_status()

    ctype = resp.headers.get("Content-Type", "").lower()
    if ctype and "html" not in ctype:
        raise ValueError(f"not HTML (Content-Type: {ctype.split(';')[0]})")

    body = b""
    for chunk in resp.iter_content(65536):
        body += chunk
        if len(body) > MAX_BYTES:
            raise ValueError("page too large")
    resp.close()

    encoding = resp.encoding or "utf-8"
    return body.decode(encoding, errors="replace"), resp.url


def process(url, label, timeout, insecure, save_html_dir):
    """Fetch one URL and extract its features. Returns a row dict or None."""
    try:
        html, final_url = fetch(url, timeout, insecure)
    except Exception as exc:
        return {"_error": f"{type(exc).__name__}: {exc}", "_url": url}

    if save_html_dir:
        # Keep the raw page. If you ever change how a feature is calculated,
        # you can re-extract from these instead of refetching pages that will
        # be long dead by then. Worth the disk space.
        name = sha1(url.encode()).hexdigest()[:16] + ".html"
        with open(os.path.join(save_html_dir, name), "w", encoding="utf-8") as fh:
            fh.write(html)

    try:
        feats = extract_features(html, page_url=final_url)
    except Exception as exc:
        return {"_error": f"extract failed: {exc}", "_url": url}

    feats["file_name"] = url
    feats["label"] = label
    return feats


def main():
    ap = argparse.ArgumentParser(description="Collect training data from URLs.")
    ap.add_argument("urls", help="text file of URLs, or CSV with a 'url' column")
    ap.add_argument("--label", type=int, required=True,
                    help="1 = phishing, 0 = benign")
    ap.add_argument("--out", required=True, help="output CSV")
    ap.add_argument("--save-html", default=None,
                    help="folder to keep raw HTML in (recommended)")
    ap.add_argument("--workers", type=int, default=8,
                    help="parallel downloads (keep modest, be polite)")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--limit", type=int, default=None,
                    help="stop after this many URLs")
    ap.add_argument("--secure", action="store_true",
                    help="enforce SSL certificate checks (loses many phishing sites)")
    args = ap.parse_args()

    if args.label not in (0, 1):
        sys.exit("--label must be 0 (benign) or 1 (phishing)")

    urls = read_urls(args.urls)
    done = already_done(args.out)
    todo = [u for u in urls if u not in done]
    if args.limit:
        todo = todo[: args.limit]

    if not todo:
        print(f"Nothing to do. {len(done)} URL(s) already collected in {args.out}")
        return

    print(f"{len(urls)} URL(s) in input, {len(done)} already done, "
          f"{len(todo)} to fetch.")

    if args.save_html:
        os.makedirs(args.save_html, exist_ok=True)

    columns = ["file_name"] + FEATURE_ORDER + ["label"]
    new_file = not os.path.exists(args.out)

    ok = fail = 0
    errors = []

    # Append row by row rather than holding everything in memory, so a crash
    # halfway through still leaves you with everything collected so far.
    with open(args.out, "a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns)
        if new_file:
            writer.writeheader()

        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {}
            for u in todo:
                futures[pool.submit(process, u, args.label, args.timeout,
                                    not args.secure, args.save_html)] = u
                time.sleep(random.uniform(0.05, 0.15))  # gentle pacing

            for i, fut in enumerate(as_completed(futures), 1):
                row = fut.result()
                if "_error" in row:
                    fail += 1
                    errors.append((row["_url"], row["_error"]))
                else:
                    writer.writerow({k: row[k] for k in columns})
                    ok += 1
                if i % 25 == 0 or i == len(todo):
                    fh.flush()
                    print(f"  {i}/{len(todo)}  ok={ok} failed={fail}", flush=True)

    print(f"\nDone. {ok} collected, {fail} failed. Written to {args.out}")

    if errors:
        log = args.out + ".errors.txt"
        with open(log, "w", encoding="utf-8") as fh:
            for u, e in errors:
                fh.write(f"{u}\t{e}\n")
        print(f"Failures logged to {log}")
        print("\nMost failures are normal — phishing pages get taken down fast.")


if __name__ == "__main__":
    main()
