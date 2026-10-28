# Phishing Email Investigator

A Python-based email triage tool for examining `.eml` files offline. It extracts email metadata, authentication results, message content, URLs, and attachments, then highlights suspicious indicators using heuristic rules.

## Features

- Parse email headers and MIME content.
- Extract URLs without visiting them.
- Identify suspicious indicators.
- Calculate a heuristic risk score.
- Generate investigation reports.
- Analyze multiple emails and export CSV summaries.
- Optionally enrich sender-domain information using VirusTotal.
- Run automated unit tests.

## Requirements

- Python 3.10 or later.
- No third-party packages required for the core analyzer.
- A VirusTotal API key is needed only for VirusTotal lookups.

## Usage

Analyze an email:

```bash
python main.py --email /path/to/message.eml
```

Save a report:

```bash
python main.py --email /path/to/message.eml --report report.txt
```

Optionally query the sender domain through VirusTotal:

```bash
export VT_API_KEY="YOUR_API_KEY"
python main.py --email /path/to/message.eml --virustotal
```

Analyze a directory of emails:

```bash
python batch_analyze.py --directory /path/to/emails --limit 25 --output results.csv
```

Run tests:

```bash
python -m unittest discover -s tests -v
```

## Safety and limitations

- The core analyzer examines email content locally and does not need to open extracted URLs.
- VirusTotal lookups contact an external service; consider privacy before submitting indicators.
- Heuristic scores are not standardized threat ratings and can produce false positives or false negatives.
- SPF and DKIM passing do not prove the sender is authorized to represent a claimed brand.
- Zero detections or a missing reputation report do not prove an indicator is safe.
- Analyze only emails you are authorized to examine. Remove sensitive information from reports before sharing them publicly.

## Project status

An educational cybersecurity project for learning and authorized email triage.
