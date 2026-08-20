# Phishing Detector — Start Up Folder

Freddie's project. Last updated: 6 August 2026.

**If you forget everything else, read this bit.**

You have built a thing that looks at a web page and says whether it's a
phishing page. It works. It's about as good as the published research on the
same data. It is not yet something you can sell, for one specific legal reason
explained below, and there is one known weakness you need to fix before it's a
real product.

---

## What is this, in plain words?

Phishing pages are fake websites that pretend to be your bank, your email
provider, whatever — so you type your password in and the attacker steals it.

You built a system that spots them. It works in two parts:

**Part 1 — the extractor.** It opens a web page and measures 13 things about
it. Not what the page *says*, but how it's *built*. How many HTML tags. How
many login forms. How much JavaScript, and how scrambled that JavaScript looks.
How many links point off to other websites versus staying on this one. Think of
it like a building inspector who never reads the sign on the door — they just
measure the walls, count the exits, check the wiring.

**Part 2 — the model.** It takes those 13 measurements and gives a score from
0 to 1. Higher means more likely phishing. Anything at or above 0.30 gets
called PHISHING.

The extractor was the missing piece until now. Before, your model could only
read 13 numbers that somebody else had already worked out. Now you can point
it at an actual web page.

---

## How do I run it?

### Windows quick start

This folder lives at `C:\Users\USER\Desktop\startup`.

**Open a terminal in the right place.** Open the `startup` folder in File
Explorer, click the address bar at the top, type `cmd`, press Enter. A black
window opens already pointed at this folder. (Doing it this way saves you
typing out the path.)

**One-time setup.** In that window:

```
py -m pip install scikit-learn pandas beautifulsoup4 lxml joblib requests
```

If `py` isn't recognised, try `python` instead. If neither works, Python isn't
installed — get it from python.org and tick **"Add Python to PATH"** during
install, which is the box everyone misses.

**Then, to scan things:**

```
py scan.py data\phishy.html              a single file
py scan.py data\                         every HTML file in a folder
py scan.py https://example.com           a live website
py scan.py data\ --csv results.csv       save results to a spreadsheet
py scan.py data\ --threshold 0.5         be less trigger-happy
```

Note Windows uses back-slashes `\` in paths where Mac and Linux use `/`.

### Mac or Linux

Same thing, with `python3` instead of `py` and forward slashes:

```
pip install scikit-learn pandas beautifulsoup4 lxml joblib requests
python3 scan.py data/phishy.html
```

### What you'll see

You'll get something like:

```
!! 0.695  PHISHING  phishy.html
   0.112  benign    normal_site.html
```

---

## Building your own data (collect.py)

This is how you escape both problems above. Read that section first if you've
forgotten why you're doing this.

**What it does:** takes a list of URLs, downloads each page, measures the same
13 things, and writes a CSV in the exact same shape as the training data you
already have.

```
py collect.py phish_urls.csv --label 1 --out phish.csv --save-html raw\
py collect.py benign_urls.txt --label 0 --out benign.csv --save-html raw\
```

`--label 1` means phishing, `--label 0` means benign. Input can be a plain
text file (one URL per line) or a CSV with a `url` column, which is what
PhishTank exports.

**Always use `--save-html`.** It keeps a copy of every page it downloads. If
you later change how a feature is calculated, you can re-measure those saved
copies instead of refetching — and by then the phishing pages will be long
dead and gone forever. Cheap insurance.

**You can stop it any time.** Close the window, lose your connection, whatever.
Run the same command again and it picks up where it left off, skipping URLs
it already has.

**Expect lots of failures.** Phishing sites get taken down within hours of
being reported, so a large share of any PhishTank list will already be dead.
That's normal, not a bug. Failures are logged to a `.errors.txt` file. Run
collection repeatedly over days or weeks rather than expecting one big haul.

### Where to get URLs

- **Phishing:** PhishTank (phishtank.org) publishes a live feed of reported
  phishing URLs. Free with an API key. **Check their terms for commercial use
  before you build on it** — you've been caught by a licence once already.
- **Benign:** the Tranco list (tranco-list.eu) ranks popular domains. But do
  not use only that — it's big famous sites, which is exactly the mistake that
  created Problem 2. Deliberately gather small, plain business websites too.
  Local directories and small-business listings are good hunting grounds.

Aim for roughly balanced numbers of each, as your current data is.

### A note on certificates

Phishing sites frequently have broken or fake SSL certificates, so by default
the collector doesn't check them — otherwise you'd lose most of your samples.
This is safe here **only because the collector never opens or runs anything
it downloads**, it just reads the text. Pass `--secure` if you want strict
checking.

---

## What's in this folder?

| File | What it is |
| --- | --- |
| `README.md` | This file. |
| `CODE_EXPLAINED.md` | Plain-language walkthrough of every script. |
| `scan.py` | **The thing you run.** Page in, verdict out. |
| `collect.py` | Builds your own training data from a list of URLs. |
| `extract_features.py` | The extractor. Measures the 13 things. Used by both scripts. |
| `phishing_html_model.joblib` | The trained model. The brain. |
| `model_metrics.json` | How well it scores, in numbers. |
| `html_feature_spec.md` | Exact definition of each of the 13 measurements, from the research paper. |
| `data/HTML_Top13_Features.csv` | The training data. ~20,000 pages. |
| `data/phishy.html` | A fake phishing page for testing. |
| `data/realistic_benign.html` | A fake normal page for testing. |

---

## The API

There is now an HTTP service wrapping all of this — see
[`docs/API.md`](docs/API.md).

```
python -m pip install -r requirements.txt
python -m api.keys create --name "you"
uvicorn api.main:app --reload --port 8000
```

Dashboard at http://localhost:8000/, interactive docs at
http://localhost:8000/docs.

**Requires Python 3.11 or newer.** The model bundle is pickled with
scikit-learn 1.8.0, which has no wheels for 3.10; running on 3.10 forces
1.7.2 and warns that predictions may be invalid.

---

## How good is it, honestly?

Tested properly (5-fold cross-validation, meaning the model was repeatedly
tested on pages it had never seen):

- **Catches 96.7%** of phishing pages.
- **Misses 328** out of roughly 10,000 phishing pages.
- **Falsely accuses 1,263** out of roughly 10,000 innocent pages — about 1 in 8.
- **ROC-AUC 0.9845** — a measure of how well it separates the two groups,
  where 1.0 is perfect and 0.5 is a coin flip.

**Context that matters:** the researchers who built this dataset got an F1
score of 0.9386 with Random Forest on the same 13 features. You're in the same
place. You are not behind. HTML is genuinely the hardest of their file types —
they got near-perfect scores on Word and PDF, because real web pages are messy
in a way that document files aren't.

### The threshold is a dial, not a fact

0.30 is aggressive. It's set to catch as much phishing as possible, and it
pays for that with false alarms. Raise it to 0.50 and you'll accuse far fewer
innocent pages but let more phishing through.

Which setting is right depends entirely on who's using it. A consumer browser
extension should probably catch more and tolerate false alarms. A security firm
drowning in alerts wants the opposite. **This dial being adjustable per
customer is a genuine product feature, not a flaw.**

---

## Two problems you must not forget

### Problem 1: You cannot legally sell this yet

The CIC-Trap4Phish dataset is licensed **CC BY-NC 4.0**. The NC means
**non-commercial**. You may use it to learn, to build your portfolio, and to
publish research — with a citation. You may **not** build a business on it.

This is not a technicality you can argue your way around.

**The escape route.** The research paper says exactly where they got their
data: malicious pages from **PhishTank**, benign pages **crawled from Google**.
Both are available to you directly. Now that you have a working extractor, you
can go and collect your own pages from those same sources, run your extractor
over them, and train on the result. That dataset is yours. No licence, no
restriction.

**So the extractor isn't just the bridge to a product — it's the way out of the
licence trap.** That's why it was the right thing to build first.

Required citation while you're using their data:

> Nejati, F., Rabbani, M., Mirani, M., Piya, G., Opushnyev, I., Ghorbani,
> A. A., & Dadkhah, S. (2026). CIC-Trap4Phish: A Unified Multi-Format Dataset
> for Phishing and Quishing Attachment Detection. arXiv:2602.09015.

### Problem 2: It's biased against small, simple websites

This one is subtle and it matters commercially.

Look at the training data. Benign pages have a **median of 514 HTML tags**.
Malicious pages have **91**. The researchers got their benign pages by
crawling Google and Wikipedia — big, mature, complicated sites. Their phishing
pages are phishing kits, which are small and simple by nature.

So the model has partly learned a shortcut: **"small and simple means
phishing."**

Test it yourself. `data/realistic_benign.html` is a perfectly innocent bakery
website. It scores 0.365 and gets flagged.

Why this is a business problem: you picked this product because small
businesses and individuals are your buyers. A small business with a clean,
simple one-page site is exactly what this model wrongly accuses. Your customer
and your blind spot are the same people.

**The fix** is the same as the licence fix — collect your own benign pages
from small, ordinary websites, not just Wikipedia-scale ones. Same solution
to both problems.

---

## Where you are, and what's next

**Done:**
1. Trained a model matching published research quality.
2. Found the exact feature definitions from the paper.
3. Built the extractor, so raw pages work now.
4. Connected extractor to model — end-to-end scanning works.

**The immediate next job — validation.** The extractor's logic is sound and
tested, but it has *not* been checked against the researchers' own numbers.
That check is the important one, and it goes like this:

1. Download the raw HTML sample files from the UNB dataset page.
2. Run the extractor over them.
3. Compare your numbers to the rows in `HTML_Top13_Features.csv`, matching on
   the `file_name` column.
4. If `tag_count` for a given file matches theirs, you're good. If not, adjust.

If your extractor computes things even slightly differently from theirs, the
model will quietly get worse on real pages without ever throwing an error.
That's the failure mode to fear.

The three most likely places for a mismatch are flagged in
`html_feature_spec.md`: `min_link_length` when a page has no links,
`script_entropy` (average across script blocks vs. one big blob), and the two
whitespace ratios, which sound identical but measure different things.

**After that:** collect your own data from PhishTank and ordinary small
websites, retrain, and you have something you own outright and can sell.

---

## A note on safety

The extractor **downloads pages but never opens or runs them**. It reads the
HTML as plain text. That's the entire reason the research used "static"
features. Don't change this — if you start rendering pages in a real browser to
get better measurements, you're executing attacker-controlled code on your own
machine.

Useful links:

- Dataset: https://www.unb.ca/cic/datasets/trap4phish2025.html
- Paper: https://arxiv.org/abs/2602.09015
