# SentinelLite — Authentication Log Analyzer

SentinelLite is a beginner-friendly defensive cybersecurity project. It parses authentication logs, flags repeated failed login attempts within a configurable time window, presents results in a Streamlit dashboard, and calculates a SHA-256 digest of the uploaded log file.

## Features
- Parse timestamp, IP address, username, and authentication status
- Detect repeated failed logins with a sliding time window
- Configurable alert threshold and window
- Streamlit dashboard and incident-summary export
- SHA-256 file integrity digest
- Synthetic sample data for safe demonstration

## Requirements
- Python 3.10+
- See `requirements.txt`

## Run locally
```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
streamlit run app.py
```

Open the local URL shown by Streamlit. Choose **Load synthetic demo** from the sidebar, or upload a log file.

## Log format
One event per line:
```text
YYYY-MM-DD HH:MM:SS,IP_ADDRESS,USERNAME,SUCCESS_OR_FAILED
```
Example:
```text
2026-11-04 10:10:00,192.168.1.105,alice,FAILED
```

## Detection logic
The app groups failed events by IP and checks whether at least the configured number occur within the configured time window. It is a simple heuristic: a flag is an investigation lead, not proof of malicious activity. Real-world deployments need more log formats, careful time handling, access controls, and tuning.

## Project safety
Use only synthetic data or logs you own / have explicit authorization to analyze. Do not upload confidential production logs to public services.

## Project structure
- `app.py` — parser, detection logic, dashboard, report export, and SHA-256 digest
- `requirements.txt` — Python dependencies
- `Project_Report.pdf` — project report

## GitHub
Create a new repository named `SentinelLite`, then upload `app.py`, `requirements.txt`, `README.md`, and `Project_Report.pdf`. Keep secrets and real authentication logs out of the repository.
