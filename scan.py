"""
End-to-end phishing scanner: raw HTML in, verdict out.

Chains the feature extractor to the trained Extra Trees model so you can
point it at a page instead of a pre-computed feature row.

    python scan.py page.html
    python scan.py folder_of_html/
    python scan.py https://example.com          (needs `requests` + network)

Options:
    --model PATH      model bundle (default: phishing_html_model.joblib)
    --threshold N     override the saved threshold
    --csv PATH        write results to CSV instead of printing
"""

import argparse
import os
import sys

import joblib
import pandas as pd

from extract_features import FEATURE_ORDER, extract_from_file, extract_from_url

DEFAULT_MODEL = "phishing_html_model.joblib"


def load_bundle(path):
    if not os.path.exists(path):
        sys.exit(
            f"Model not found at {path}\n"
            "Point --model at your phishing_html_model.joblib file."
        )
    bundle = joblib.load(path)
    model = bundle["model"]
    threshold = bundle["threshold"]
    features = bundle["features"]

    # Guard against silent misalignment: if the extractor's feature order
    # ever drifts from the model's, predictions become garbage without
    # raising an error. Catch it here instead.
    if list(features) != list(FEATURE_ORDER):
        sys.exit(
            "Feature mismatch between extractor and model.\n"
            f"  model expects: {list(features)}\n"
            f"  extractor gives: {list(FEATURE_ORDER)}\n"
            "Fix FEATURE_ORDER in extract_features.py before scanning."
        )
    return model, threshold, features


def gather(target):
    """Return a list of (label, feature_dict) for whatever was pointed at."""
    items = []
    if target.startswith(("http://", "https://")):
        items.append((target, extract_from_url(target)))
    elif os.path.isdir(target):
        for name in sorted(os.listdir(target)):
            if name.lower().endswith((".html", ".htm")):
                items.append((name, extract_from_file(os.path.join(target, name))))
    elif os.path.isfile(target):
        items.append((os.path.basename(target), extract_from_file(target)))
    else:
        sys.exit(f"Not a file, folder, or URL: {target}")
    return items


def main():
    ap = argparse.ArgumentParser(description="Scan HTML for phishing.")
    ap.add_argument("target", help="HTML file, folder of HTML files, or URL")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--threshold", type=float, default=None)
    ap.add_argument("--csv", default=None)
    args = ap.parse_args()

    model, saved_threshold, features = load_bundle(args.model)
    threshold = args.threshold if args.threshold is not None else saved_threshold

    items = gather(args.target)
    if not items:
        sys.exit("No HTML found to scan.")

    X = pd.DataFrame([f for _, f in items])[features]
    probs = model.predict_proba(X)[:, 1]

    rows = []
    for (label, feats), p in zip(items, probs):
        rows.append(
            {
                "target": label,
                "phishing_probability": round(float(p), 4),
                "verdict": "PHISHING" if p >= threshold else "benign",
            }
        )

    df = pd.DataFrame(rows)

    if args.csv:
        df.to_csv(args.csv, index=False)
        print(f"Wrote {len(df)} result(s) to {args.csv}")
        return

    print(f"\nThreshold: {threshold}  (score at or above this = PHISHING)\n")
    for r in rows:
        mark = "!!" if r["verdict"] == "PHISHING" else "  "
        print(f"{mark} {r['phishing_probability']:.3f}  {r['verdict']:9s} {r['target']}")
    print()


if __name__ == "__main__":
    main()
