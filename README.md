# SentinelAI

A lightweight AI-assisted SIEM prototype for monitoring an Ubuntu virtual machine.
Built as a university cybersecurity project.

---

## Project Structure

```
sentinelai/
├── backend/
│   ├── main.py              # FastAPI entry point
│   ├── config.py            # All constants: paths, event types, thresholds
│   ├── collector.py         # Reads log files, dispatches to parsers
│   ├── parser_auth.py       # Parses /var/log/auth.log
│   ├── parser_syslog.py     # Parses /var/log/syslog          [Week 2]
│   ├── parser_custom.py     # Parses custom_security.log      [Week 2]
│   ├── normalizer.py        # build_event() — common event format
│   ├── aggregator.py        # Groups events into sessions      [Week 2]
│   ├── detection.py         # Rule-based detection engine      [Week 3]
│   ├── correlation.py       # Links alerts into incidents      [Week 3]
│   ├── anomaly_scoring.py   # Isolation Forest ML scoring      [Week 4]
│   ├── risk_scoring.py      # Final 0–100 risk score           [Week 4]
│   ├── storage.py           # SQLite database layer            [Week 1 Day 5]
│   ├── schemas.py           # Pydantic API models
│   └── utils.py             # Shared utilities
├── frontend/                # HTML/CSS/JS dashboard            [Week 5]
├── database/                # sentinelai.db (auto-created)
├── data/logs/               # Log files copied from Ubuntu VM
│   ├── auth.log
│   ├── syslog
│   └── custom_security.log
├── models/                  # Trained ML model files
├── scripts/                 # Helper scripts (SCP transfer etc.)
├── tests/
│   └── test_parser_auth.py
└── requirements.txt
```

---

## Setup

```bash
# 1. Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/macOS

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the API server
cd backend
uvicorn main:app --reload --port 8000
```

---

## Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

---

## Log Sources

| File | Source | Parser |
|------|--------|--------|
| `data/logs/auth.log` | Ubuntu `/var/log/auth.log` | `parser_auth.py` |
| `data/logs/syslog` | Ubuntu `/var/log/syslog` | `parser_syslog.py` |
| `data/logs/custom_security.log` | Custom VM script | `parser_custom.py` |

Copy logs from the Ubuntu VM using SCP:
```bash
scp user@<vm-ip>:/var/log/auth.log data/logs/auth.log
scp user@<vm-ip>:/var/log/syslog   data/logs/syslog
```

---

## Week-by-Week Plan

| Week | Focus |
|------|-------|
| 1 | Skeleton, config, collector, parser_auth, normalizer, storage, schemas |
| 2 | parser_syslog, parser_custom, aggregator |
| 3 | detection (rules), correlation (incidents) |
| 4 | anomaly_scoring (Isolation Forest), risk_scoring |
| 5 | FastAPI endpoints, frontend dashboard |
| 6 | Attack simulations, testing, polish |
