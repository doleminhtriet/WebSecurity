# Web Security Capstone – Engineering Notes

## Overview
- FastAPI service (`apps/api/main.py`) backed by a small set of security modules.
- Static dashboard in `public/` (served under `/app`) links to each module.
- MongoDB logging wired into phishing/malware (PCAP skips inserts for now).

| Module | REST prefix | UI entry point | Description |
| --- | --- | --- | --- |
| Scan Phishing | `/phishing` | `public/phishing.html` | TF‑IDF + logistic regression classifier with optional URL features. |
| Scan Malware | `/malware` | `public/malware.html` | Heuristic file scanner (entropy, strings, headers). Logs to Mongo. |
| PCAP Analyzer | `/pcap` | `public/pcap.html` | Scapy-powered capture summary + SYN flood heuristic. |

## Prerequisites
- Python 3.11+ (project built/tested on 3.13).
- MongoDB URI (Atlas or self-hosted) if you want logging enabled.
- For PCAP analysis, libpcap prerequisites depend on your platform; install `scapy` wheel requirements (already handled by requirements file).

## Quick Start
```bash
python3 -m venv .venv
source .venv/bin/activate              # Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt        # includes FastAPI, scikit-learn, scapy, pymongo, etc.
```

Configure environment (copy `.env` as needed):
```bash
cp .env.example .env    # create if you want to keep secrets out of git
```
Key variables:
- `MONGODB_URI` – Atlas/SRV URI. Leave blank to disable logging.
- `PHISH_CFG` – path to YAML config (`config/base.yaml` by default).

Run the API:
```bash
uvicorn apps.api.main:app --reload
```
Open the UI at `http://127.0.0.1:8000/app/index.html`.

## Module Details

### Phishing Scanner
- Artifacts live in `modules/scan_phishing/artifacts/` (vectorizer + model).
- Training data in `data/phishing/train.csv` and `valid.csv`.
- CLI helper:
  ```bash
  python -m modules.scan_phishing.cli train --config config/base.yaml
  python -m modules.scan_phishing.cli predict --text "example email"
  ```
- Mongo collection: `predictions` (configurable via `config/base.yaml`).

### Malware Scanner
- Heuristic engine in `modules/scan_malware/scanner.py`.
- API `/malware/scan` accepts file uploads; UI wraps it in `public/malware.html`.
- Logs every scan to the `malware` collection when Mongo is configured.
- CLI helper:
  ```bash
  python -m modules.scan_malware.cli sample.exe
  ```

### PCAP Analyzer
- Requires Scapy (included in `requirements/base.txt`).
- Endpoint `/pcap/analyze` returns stats + SYN flood findings.
- Front-end upload page: `public/pcap.html`.
- If Scapy is missing the API returns HTTP 503 with a descriptive message.

## Configuration (`config/base.yaml`)
- `mongodb` section toggles logging and TLS behaviour.
- `phishing` and `malware` sections expose thresholds, feature flags, etc.
- Adjust `malware.threshold` (default 0.6) to tune alerting.
- `phishing.threshold` (default 0.9) controls LEGIT vs PHISH cut-off on the API.

## MongoDB Helpers
- Quick connectivity script: `python modules/test/test_mongo.py --insert`.
- All log documents include timestamps (UTC) and basic metadata (hash, filename, source).

## Training Workflow (Phishing)
1. Expand `data/phishing/train.csv` / `valid.csv` with labeled emails (`text,label`).
2. Run `python -m modules.scan_phishing.cli train`.
3. New artifacts drop into `modules/scan_phishing/artifacts/`.
4. Restart API or `POST /phishing/reload` to pick up updated artifacts.

## Development Notes
- Requirements split:
  - `requirements/base.txt` – runtime dependencies (includes Scapy, numpy, etc).
  - `requirements/phishing.txt` – placeholder for future model-specific extras.
- Static UI assets are plain HTML/CSS/JS (no build step required).
- When adding a new module, follow the same pattern: FastAPI router under `modules/<module>/service.py`, optional CLI, static page under `public/`.
- Remember to update `apps/api/main.py` to include new routers and adjust `public/index.html` card text.

## Running Tests
Currently only helper scripts; no automated unit tests ship with the repo. Recommended checks:
- `python modules/test/test_mongo.py --insert --cleanup`
- Add your own pytest suite under `modules/test/` if needed.

## Troubleshooting
- **Mongo SSL errors**: ensure `certifi` is installed (pulled via requirements) and Atlas IP allow-list includes your public IP.
- **Scapy missing**: reinstall requirements (`pip install -r requirements.txt`) or manually `pip install scapy`.
- **PCAP upload 404**: verify UI points to `/pcap/analyze` and API router is mounted (`apps/api/main.py`).
- **Phishing classifier mislabels**: gather more labeled email samples, retrain, and tune threshold.

---

Maintainers can extend this README as modules mature (e.g., add reporting workflows or CI instructions). Merge requests should update this document whenever setup steps change.
