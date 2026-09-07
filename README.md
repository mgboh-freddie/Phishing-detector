# Phishing Detector

A machine learning based phishing detection system that analyzes the structure and content of HTML pages to determine whether a webpage is likely to be legitimate or phishing.

The system combines a static HTML feature extractor with a trained machine learning model and supports scanning individual HTML files, directories, and live URLs.

## Overview

Phishing websites are designed to imitate legitimate websites in order to trick users into revealing sensitive information such as passwords, financial details, or personal data.

This project detects potentially malicious webpages by analyzing **13 static HTML features** rather than executing the webpage in a browser.

The system works in two main stages:

1. **Feature Extraction**
   The HTML page is analyzed to extract 13 structural features, including HTML tag counts, forms, JavaScript characteristics, links, and other page-level properties.

2. **Machine Learning Classification**
   The extracted features are passed to a trained machine learning model that produces a probability score between 0 and 1.

A score at or above the default threshold of **0.30** is classified as `PHISHING`.

```text
HTML Page / URL
       ↓
Feature Extraction
       ↓
13 HTML Features
       ↓
Machine Learning Model
       ↓
Probability Score
       ↓
PHISHING / BENIGN
```

## Features

The project currently supports:

- HTML file scanning
- Directory scanning
- Live URL scanning
- Automatic HTML feature extraction
- Phishing probability scoring
- Configurable classification threshold
- CSV result export
- Dataset collection from URLs
- REST API
- Interactive API documentation

## Installation

### Requirements

- Python 3.11 or newer
- pip

The API and model bundle currently require Python 3.11 or newer because the trained model was created using scikit-learn 1.8.0.

### Install dependencies

```bash
python -m pip install -r requirements.txt
```

If you are using the command-line scanner without the requirements file, install:

```bash
python -m pip install scikit-learn pandas beautifulsoup4 lxml joblib requests
```

## Usage

### Scan a single HTML file

```bash
python scan.py data/phishy.html
```

### Scan all HTML files in a directory

```bash
python scan.py data/
```

### Scan a live website

```bash
python scan.py https://example.com
```

### Save results to CSV

```bash
python scan.py data/ --csv results.csv
```

### Change the classification threshold

```bash
python scan.py data/ --threshold 0.5
```

The threshold controls how sensitive the classifier is.

A lower threshold generally increases phishing detection but can also increase false positives.

A higher threshold reduces false positives but may allow more phishing pages to pass undetected.

## Example Output

```text
!! 0.695  PHISHING  phishy.html
   0.112  BENIGN    normal_site.html
```

The numerical value represents the model's phishing probability.

## Building a Dataset

The project includes `collect.py`, which can collect webpages from a list of URLs and extract the same 13 features used by the trained model.

### Collect phishing pages

```bash
python collect.py phish_urls.csv --label 1 --out phish.csv --save-html raw/
```

### Collect benign pages

```bash
python collect.py benign_urls.txt --label 0 --out benign.csv --save-html raw/
```

`--label 1` represents phishing pages.

`--label 0` represents benign pages.

The input can either be:

- A plain text file containing one URL per line
- A CSV file containing a `url` column

The `--save-html` option stores downloaded HTML pages locally. This makes it possible to re-extract features later without downloading the pages again.

Websites may become unavailable after collection, particularly phishing websites, so preserving the downloaded HTML is useful for reproducible experimentation.

## Data Sources

For future dataset development, the project is designed to work with:

### Phishing URLs

Phishing URLs can be sourced from PhishTank.

### Benign URLs

Benign websites can be collected from domain-ranking sources such as the Tranco list, while also including smaller and less complex websites to improve dataset diversity.

The dataset should contain a reasonably balanced representation of phishing and benign examples.

## Model Performance

The model was evaluated using **5-fold cross-validation**.

Current results:

| Metric | Result |
|---|---:|
| Phishing Detection Rate | **96.7%** |
| ROC-AUC | **0.9845** |
| False Negatives | **328 / ~10,000 phishing pages** |
| False Positives | **1,263 / ~10,000 benign pages** |

The model achieves a high ROC-AUC, indicating strong separation between the phishing and benign classes within the evaluation dataset.

The results are also broadly comparable to the published research associated with the dataset, which reported an F1 score of 0.9386 using Random Forest on the same 13 HTML features.

## Classification Threshold

The default classification threshold is:

```text
0.30
```

This threshold prioritizes detecting phishing pages, but it also results in more false positives.

The threshold can be changed depending on the intended application.

For example:

```bash
python scan.py data/ --threshold 0.50
```

A lower threshold may be appropriate where missing a phishing page is considered more costly.

A higher threshold may be preferable in environments where false positives generate significant operational overhead.

## API

The project includes an HTTP API that provides access to the phishing detection system.

### Start the API

Install the project requirements:

```bash
python -m pip install -r requirements.txt
```

Create an API key:

```bash
python -m api.keys create --name "you"
```

Start the server:

```bash
uvicorn api.main:app --reload --port 8000
```

The local dashboard is available at:

```text
http://localhost:8000/
```

Interactive API documentation:

```text
http://localhost:8000/docs
```

For detailed API information, see:

```text
docs/API.md
```

## Project Structure

```text
Phishing-detector/
│
├── README.md
├── CODE_EXPLAINED.md
├── scan.py
├── collect.py
├── extract_features.py
├── phishing_html_model.joblib
├── model_metrics.json
├── html_feature_spec.md
│
├── api/
│   └── ...
│
├── docs/
│   └── API.md
│
└── data/
    ├── HTML_Top13_Features.csv
    ├── phishy.html
    └── realistic_benign.html
```

### Important Files

| File | Description |
|---|---|
| `scan.py` | Command-line phishing scanner |
| `collect.py` | Collects webpages and builds feature datasets |
| `extract_features.py` | Extracts the 13 HTML features |
| `phishing_html_model.joblib` | Trained machine learning model |
| `model_metrics.json` | Model evaluation metrics |
| `html_feature_spec.md` | Definitions of the 13 HTML features |
| `api/` | HTTP API implementation |
| `docs/API.md` | API documentation |
| `data/` | Training and testing data |

## Dataset and Attribution

The initial model was trained using the **CIC-Trap4Phish** dataset.

The dataset is associated with the following research:

> Nejati, F., Rabbani, M., Mirani, M., Piya, G., Opushnyev, I., Ghorbani, A. A., & Dadkhah, S. (2026). CIC-Trap4Phish: A Unified Multi-Format Dataset for Phishing and Quishing Attachment Detection. arXiv:2602.09015.

Research paper:

https://arxiv.org/abs/2602.09015

Dataset:

https://www.unb.ca/cic/datasets/trap4phish2025.html

The dataset should be used according to its applicable license and attribution requirements.

## Limitations

Although the model performs well on the evaluation dataset, there are important limitations to consider before using it in a production security environment.

### Dataset Bias

The current training dataset contains differences between benign and phishing webpages that may not fully represent the diversity of the modern web.

For example, the benign pages in the dataset tend to contain significantly more HTML elements than the phishing pages.

This creates a potential shortcut for the model, where relatively small and simple webpages may receive higher phishing scores even when they are legitimate.

A test using the included `realistic_benign.html` page demonstrates this limitation.

### False Positives

The current model produces false positives alongside its high phishing detection rate.

This means the model should not be treated as an unquestionable security verdict.

For production applications, model predictions should ideally be combined with additional security signals and validation mechanisms.

### Dataset Licensing

The initial dataset has restrictions on commercial use.

For a commercial deployment, the model should be retrained using appropriately sourced data with licensing terms that permit the intended use.

## Security Considerations

The feature extractor uses **static HTML analysis**.

Downloaded webpages are treated as text and are not rendered or executed in a browser.

This is an important security property because rendering an attacker-controlled webpage can execute JavaScript or trigger other browser behavior.

The current architecture intentionally avoids executing downloaded webpage content.

## Roadmap

### Completed

- [x] Train initial phishing classification model
- [x] Identify and implement the 13 HTML features
- [x] Build the HTML feature extractor
- [x] Connect feature extraction to the trained model
- [x] Implement command-line scanning
- [x] Add URL scanning
- [x] Add CSV result export
- [x] Build URL dataset collection pipeline
- [x] Add HTTP API

### Planned

- [ ] Validate extracted features against the original dataset
- [ ] Build a more representative benign dataset
- [ ] Collect additional phishing samples
- [ ] Retrain the model using the expanded dataset
- [ ] Evaluate additional machine learning algorithms
- [ ] Improve false-positive performance
- [ ] Add more comprehensive API testing
- [ ] Deploy the detection API

## Disclaimer

This project is intended for research, education, and security experimentation.

A machine learning prediction should not be treated as definitive proof that a webpage is malicious or legitimate.

Always combine automated detection with appropriate security controls and human review where necessary.

## Author

**Freddie Mgboh**

Electronics Engineering | Software Engineering | Data Science & Machine Learning

GitHub:

https://github.com/mgboh-freddie

## License

See the dataset and project licensing information before using this project or its associated data for commercial purposes.
