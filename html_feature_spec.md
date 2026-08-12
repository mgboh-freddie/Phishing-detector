# HTML Feature Extraction Spec — 13 Features

Source: CIC-Trap4Phish (Nejati et al., 2026), Table X.
arXiv: 2602.09015 | Dataset: unb.ca/cic/datasets/trap4phish2025.html
Dataset licence: CC BY-NC 4.0 (NON-COMMERCIAL — see note at bottom)

These are the exact 13 features the trained model expects, in the order
listed in the paper. Your extractor must compute each one the same way.

---

## URL / Link features (5)

**url_punct_char_count**
Total punctuation characters across ALL extracted URLs.
Characters include: / - = ? & : . _
Note: this is a SUM across every URL on the page, not per-URL.
High counts suggest obfuscation or heavy query strings.

**url_digit_count**
Total digit characters across all extracted URLs. Summed, not averaged.
Higher in crafted or parameterised URLs.

**external_link_count**
Count of hyperlinks pointing to a DIFFERENT hostname than the page itself.
Source: <a href> elements.

**internal_link_count**
Count of hyperlinks pointing to the SAME host. Internal navigation density.

**min_link_length**
Minimum character length among all extracted URLs.
Extreme values flag shorteners or crafted links.
Edge case: decide what to return when there are zero links — check the
dataset's own distribution for the sentinel value used.

---

## Structure features (2)

**tag_count**
Total number of HTML tags in the document. Overall structural volume.

**form_count**
Number of <form> elements. Higher in credential-harvesting pages.

---

## JavaScript features (3)

**embedded_js_count**
Number of inline/embedded JavaScript blocks.
Specifically <script> elements WITHOUT an external src attribute.

**total_script_characters**
Total character count across all JavaScript blocks. Script volume proxy.

**script_entropy**
AVERAGE Shannon entropy computed over the JavaScript blocks.
Note: average across blocks, not entropy of all JS concatenated.
Elevated values suggest obfuscated or minified JS.

---

## Entropy / whitespace features (3)

**entropy**
Shannon entropy of the raw HTML source.
Higher values indicate packed or obfuscated content.

**whitespace_ratio**
Proportion of whitespace to non-whitespace in VISIBLE TEXT only
(i.e. after stripping markup).

**html_whitespace_ratio**
Whitespace proportion over the RAW HTML, including markup.
This is the complement to whitespace_ratio — compute both, they differ.

---

## Build notes

1. Validate before trusting. Run the extractor over HTML files whose
   feature values you already know, and compare your numbers against the
   dataset row for that file. If they don't match, the model's real-world
   accuracy will silently collapse.

2. Watch the three ambiguous ones: min_link_length (empty case),
   script_entropy (average vs concatenated), and the two whitespace
   ratios (visible text vs raw HTML). These are where a mismatch is
   most likely.

3. Benchmark to beat: the paper's own HTML results are F1 0.9386
   (Random Forest) and 0.9377 (XGBoost). Not 0.98 — that figure refers
   to other formats.

---

## Licence

CIC-Trap4Phish is CC BY-NC 4.0. Non-commercial use only, with citation.
Fine for learning, portfolio, and research. NOT for a commercial product.

Path to commercial use: the paper states malicious HTML was sourced from
PhishTank and benign pages crawled from Google. Once this extractor works,
collect your own samples from those sources and build your own dataset.
Your extractor code and your own collected data carry no such restriction.

Citation:
Nejati, F., Rabbani, M., Mirani, M., Piya, G., Opushnyev, I.,
Ghorbani, A. A., & Dadkhah, S. (2026). CIC-Trap4Phish: A Unified
Multi-Format Dataset for Phishing and Quishing Attachment Detection.
arXiv preprint arXiv:2602.09015.
