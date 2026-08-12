# Code Explained

A plain-language walkthrough of every meaningful piece of code in this
project. Read alongside the actual files.

Three scripts, and they stack:

```
extract_features.py   measures a page          (the foundation)
        │
        ├── scan.py       measures + judges    (uses the foundation)
        └── collect.py    measures + collects  (uses the foundation)
```

`extract_features.py` is the one that matters. The other two are wrappers
around it. If the extractor is wrong, everything above it is wrong.

---

# 1. extract_features.py

## The imports

```python
import math, os, re, sys
from collections import Counter
from urllib.parse import urlparse
from bs4 import BeautifulSoup
```

`math` for the logarithm in entropy. `Counter` counts how often each thing
appears. `urlparse` breaks a web address into pieces — scheme, hostname, path
— so you can ask questions like "what site does this link go to?"

`BeautifulSoup` is the important one. It's an HTML parser. Raw HTML is just
a long messy string of text; BeautifulSoup turns it into a structure you can
ask questions of, like "give me every link" or "how many forms are there?"
Real-world HTML is frequently broken — unclosed tags, wrong nesting — and
BeautifulSoup copes with that instead of crashing.

## FEATURE_ORDER

```python
FEATURE_ORDER = ["url_punct_char_count", "tag_count", ...]
```

The 13 measurements, in a fixed order. **The order is not cosmetic.** The
model was trained expecting these numbers in exactly this sequence. Hand it
`tag_count` where it expects `url_punct_char_count` and it will still produce
a confident-looking answer — a wrong one, with no error. That's why `scan.py`
checks this order against the model before doing anything.

## URL_PUNCT

```python
URL_PUNCT = set("/-=?&:._")
```

The punctuation characters the research paper counts. Written as a `set`
rather than a string because checking "is this character in the set" is much
faster on a set — it matters when you're scanning thousands of pages.

## shannon_entropy

```python
def shannon_entropy(text):
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())
```

**What entropy means, in plain terms: how unpredictable is this text?**

`"aaaaaaaa"` has entropy 0 — perfectly predictable. Normal English prose sits
around 4. Random gibberish approaches 8.

Why it catches phishing: attackers scramble their JavaScript to hide what it
does. Instead of `document.location`, you get `\x64\x6f\x63...`. Scrambled
text is less predictable, so entropy rises. **High entropy is a fingerprint
of something trying to hide.**

Line by line: `Counter(text)` tallies each character. For each one we work
out its share of the text (`c / n`), then combine those shares using a
logarithm. The minus sign at the front makes the result positive, because
logarithms of fractions come out negative.

The `if not text: return 0.0` guard matters — a page with no JavaScript would
otherwise crash on dividing by zero.

## whitespace_proportion

```python
def whitespace_proportion(text):
    if not text:
        return 0.0
    return sum(1 for ch in text if ch.isspace()) / len(text)
```

What fraction of characters are spaces, tabs, or newlines. Counts the
whitespace characters, divides by the total.

Why it's a signal: hand-written pages are indented and spaced for humans to
read. Machine-generated or compressed phishing kits often aren't. It's a
rough proxy for "was a person involved in writing this?"

## collect_urls

```python
def collect_urls(soup):
    urls = []
    for tag in soup.find_all(True):
        for attr in URL_ATTRS:
            val = tag.get(attr)
            if isinstance(val, str) and val.strip():
                urls.append(val.strip())
    return urls
```

Gathers every web address on the page. `find_all(True)` means "every tag of
any kind." For each, we check the attributes that can hold a URL — `href`,
`src`, `action` and so on — and keep the non-empty ones.

`isinstance(val, str)` guards against odd HTML where an attribute isn't
plain text. `.strip()` removes stray spaces.

Note this is broader than just clickable links: it includes images, scripts,
and form targets. The paper's URL character-counting features work on all
URLs, not just hyperlinks.

## hostname_of and the two sentinels

```python
NOT_A_LINK = object()
RELATIVE = object()
```

**This is the bug fix, and it's worth understanding.**

An `href` can be three different things:

1. A full address — `https://example.com/page`
2. A relative path — `/about`, meaning "the About page on this same site"
3. Not a link at all — `mailto:me@x.com`, `javascript:void(0)`

The first version returned `None` for both "not a link" and "I don't know the
page's own address." Those are different situations that need different
handling, and conflating them meant relative links were silently discarded —
a normal website showed **zero internal links** when it plainly had several.

`object()` creates a unique marker that can't be confused with any real value.
Now the code distinguishes all three cases properly.

**Why this bug is the dangerous kind:** nothing crashed. No error appeared.
It just quietly fed wrong numbers into the model forever. Those are the bugs
to fear in machine learning — you don't find them by watching for crashes,
you find them by checking that the outputs make sense.

## extract_features — the main event

```python
soup = BeautifulSoup(html, "lxml")
```

Parse the page. `"lxml"` picks the parser — fast, and tolerant of broken HTML.

```python
base_host = (urlparse(page_url).netloc or "").lower() or None
```

Work out the page's own hostname, so we can tell internal links from external
ones. Lowercased because `EXAMPLE.COM` and `example.com` are the same site.
`page_url` is optional, but without it we can't judge internal vs external
properly — which is why `scan.py` passes it whenever it can.

### Structure

```python
tag_count = len(soup.find_all(True))
form_count = len(soup.find_all("form"))
```

Total tags, and number of forms. Forms matter enormously — a form is where
you type your password. A page with a login form is doing something a plain
article page isn't.

### JavaScript

```python
inline_scripts = [s for s in soup.find_all("script") if not s.get("src")]
```

Scripts written directly into the page, as opposed to loaded from elsewhere
via `src`. We want the inline ones because we can read their contents and
measure how scrambled they look. An external script is just a link — there's
nothing to measure without downloading it.

```python
script_entropy = sum(shannon_entropy(b) for b in script_bodies) / len(script_bodies)
```

**Average entropy across the blocks, not entropy of everything glued
together.** These give different numbers, and the paper specifies the average.
This is one of the three places flagged in `html_feature_spec.md` where a
mismatch with the researchers' method is most likely.

### Entropy and whitespace

```python
entropy = shannon_entropy(html)
html_whitespace_ratio = whitespace_proportion(html)
visible_text = soup.get_text()
whitespace_ratio = whitespace_proportion(visible_text)
```

Two whitespace measurements that sound identical but aren't. One looks at the
**raw HTML including all the tags**. The other looks at **only the text a
human would actually see**, with markup stripped out by `get_text()`.

A page can be tidy in one and messy in the other, which is exactly why the
researchers kept both.

### The link loop

```python
for a in soup.find_all("a"):
    href = a.get("href")
    if not isinstance(href, str) or not href.strip():
        continue
```

Walks through clickable links only — `<a>` tags — per the paper's definition.
Skips ones with no address.

```python
    if href.startswith("#"):
        internal_link_count += 1
        continue
```

A `#` link jumps to a spot on the same page. Internal by definition.

```python
    host = hostname_of(href)
    if host is NOT_A_LINK:
        continue
    if host is RELATIVE:
        internal_link_count += 1
    elif base_host is None:
        external_link_count += 1
    elif host == base_host:
        internal_link_count += 1
    else:
        external_link_count += 1
```

The classification. `is` rather than `==` because we're checking whether it's
that exact unique marker object, not whether it merely looks similar.

Why the counts matter: a real company website links mostly to itself — About,
Contact, Products. A phishing page has few internal pages, because it's
usually a single stolen copy, and often links away to the real company's site
to look legitimate. **The balance between internal and external is a
behavioural signature.**

## extract_from_url

```python
resp = requests.get(url, timeout=timeout, headers=headers)
return extract_features(resp.text, page_url=resp.url)
```

Downloads a live page. Two things worth noticing.

The `headers` include a browser-like User-Agent. Many sites block requests
that announce themselves as scripts, and phishing sites in particular often
serve harmless content to anything that looks automated, precisely to evade
security scanners.

`resp.url`, not `url`. If the address redirected, `resp.url` is where you
actually ended up. Judging internal-vs-external against the original address
would be wrong — and phishing URLs redirect constantly.

**The safety point:** this reads the page as text. It never renders it, never
runs its JavaScript. That's the entire reason the research uses "static"
features. Rendering attacker-controlled pages in a real browser to get better
measurements would mean executing hostile code on your own machine.

---

# 2. scan.py

The thin layer that turns measurements into a verdict.

## load_bundle — the guard

```python
if list(features) != list(FEATURE_ORDER):
    sys.exit("Feature mismatch between extractor and model...")
```

**The most important five lines in the project.**

If you ever change the extractor's feature order without retraining, or load
a model trained on a different arrangement, this stops everything and tells
you. Without it, the mismatch produces confident, professional-looking, wrong
answers with no warning at all.

Machine learning fails silently by default. Guards like this are how you make
it fail loudly instead.

## gather

```python
if target.startswith(("http://", "https://")):
elif os.path.isdir(target):
elif os.path.isfile(target):
```

Works out whether you handed it a web address, a folder, or a single file,
and behaves accordingly. Convenience, nothing clever.

## The prediction

```python
X = pd.DataFrame([f for _, f in items])[features]
probs = model.predict_proba(X)[:, 1]
```

Builds a table of measurements, then reorders the columns with `[features]`
to match what the model expects — belt and braces alongside the guard above.

`predict_proba` gives probabilities rather than a flat yes/no. It returns two
columns, one per class; `[:, 1]` takes the second, the probability of being
phishing.

**Why probabilities matter more than yes/no:** a yes/no answer has the
decision baked in permanently. A probability lets you move the line
afterwards, per customer, without retraining anything.

```python
"verdict": "PHISHING" if p >= threshold else "benign"
```

The threshold applied. `0.30` is aggressive — catches more phishing, accuses
more innocents. `0.50` is calmer. This single number is your most important
product dial.

---

# 3. collect.py

Builds your own dataset. The one that gets you out of the licence problem.

## The certificate decision

```python
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
```

Phishing sites routinely have broken, expired, or fake SSL certificates.
Enforcing certificate checks would reject most of your samples — so
verification is off by default, and this line silences the resulting flood of
warnings.

**This is only acceptable because nothing downloaded is ever executed.** We
read text and count characters. Pass `--secure` to enforce checks if you
prefer.

## MAX_BYTES

```python
MAX_BYTES = 3_000_000
```

A cap of about 3 MB. Prevents one enormous file — an accidental video link, or
a deliberate trap — from consuming your memory and stalling the run. Small
limits like this are what stop long jobs dying at 2am.

## read_urls

```python
if path.lower().endswith(".csv"):
    df = pd.read_csv(path)
    ...
```

Accepts a plain text list or a CSV with a `url` column, because that's PhishTank's
export format. You shouldn't have to reformat their file by hand.

```python
if not host or " " in host or "." not in host:
    skipped += 1
    continue
```

**The second bug fix.** Originally, a junk line reading `not a url` was
turned into `http://not a url` and accepted as valid. Scraped URL lists are
full of headers, comments, and stray text — all of which would have quietly
polluted your training data.

A real hostname has no spaces and contains a dot. Now junk is rejected and
counted, so you can see how much your input file contained.

## already_done — resume

```python
def already_done(out_path):
    if not os.path.exists(out_path):
        return set()
    df = pd.read_csv(out_path)
    return set(df["file_name"].astype(str))
```

Reads what you've already collected so a rerun skips it. Collection takes
hours; connections drop, laptops sleep, windows get closed. Without this
you'd start from nothing every time.

Uses a `set` because checking membership in a set is near-instant regardless
of size, whereas a list gets slower as it grows.

## fetch

```python
resp = requests.get(url, ..., stream=True, allow_redirects=True)
```

`stream=True` means the page arrives in chunks rather than all at once, so we
can abandon it mid-download if it exceeds the size cap.

```python
if ctype and "html" not in ctype:
    raise ValueError(f"not HTML (Content-Type: {ctype.split(';')[0]})")
```

Rejects anything that isn't a web page. Phishing URLs sometimes point straight
at a PDF or an executable, and your HTML extractor would produce meaningless
numbers from those.

```python
for chunk in resp.iter_content(65536):
    body += chunk
    if len(body) > MAX_BYTES:
        raise ValueError("page too large")
```

Downloads in 64 KB pieces, checking the size as it goes. The cap is enforced
during the download, not after — which is the point.

```python
return body.decode(encoding, errors="replace"), resp.url
```

Turns raw bytes into text. `errors="replace"` swaps unreadable characters for
a placeholder instead of crashing. Web pages come in many encodings and plenty
declare theirs wrongly; you want the run to continue, not stop.

## process — saving raw HTML

```python
name = sha1(url.encode()).hexdigest()[:16] + ".html"
```

Turns a URL into a safe filename. URLs contain slashes and question marks that
can't go in filenames; a hash produces a short unique string with none of
those. The same URL always gives the same filename.

**Why saving matters so much:** if you later change how a feature is
calculated, you can re-measure these saved pages. Without them you'd need to
refetch — and phishing pages are dead within days. **That data is
unrecoverable once lost.** Always use `--save-html`.

## The parallel download

```python
with ThreadPoolExecutor(max_workers=args.workers) as pool:
```

Downloads several pages at once. Most of the time in fetching is spent
waiting for a server to reply, so doing eight at a time is roughly eight times
faster than one after another.

```python
time.sleep(random.uniform(0.05, 0.15))
```

A brief random pause between requests. Politeness — hammering a server as
fast as possible is rude and gets you blocked. The randomness makes the
pattern less machine-like.

```python
if i % 25 == 0 or i == len(todo):
    fh.flush()
```

**Writes to disk as it goes, rather than at the end.** `flush()` forces
Python to actually commit what it's holding in memory. If the run dies at
page 900 of 1000, you keep the 900. Combined with the resume logic, an
interrupted run costs you almost nothing.

## Error logging

```python
if errors:
    log = args.out + ".errors.txt"
```

Failures go to a file rather than scrolling past in the terminal. When most
of a PhishTank batch fails — which is normal, they get taken down fast — you
want to look at *why* afterwards. If they all failed with the same error,
that's a bug to fix, not the internet being the internet.

---

# The habits worth taking from this

**Guard against silent failure.** The feature-order check in `scan.py` exists
because wrong-but-confident output is worse than a crash. In machine learning
this is the main danger, because models never refuse to answer.

**Both bugs found here were silent ones.** Dropped relative links, accepted
junk URLs. Neither crashed. Neither logged anything. You find these by
checking whether outputs make sense — a normal website having zero internal
links should look obviously wrong to you.

**Make long jobs interruptible.** Flush as you go, skip what's done. Assume
the run will be interrupted, because it will.

**Never execute what you download.** The whole approach rests on reading text
rather than running it. Don't trade that away for better measurements.
