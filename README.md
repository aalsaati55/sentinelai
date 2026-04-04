# SentinelAI

A full-stack AI-assisted SIEM (Security Information and Event Management) prototype built as a university cybersecurity project. SentinelAI ingests real Linux logs from a virtual machine, detects attacks using rule-based and ML-based engines, and presents results in a live SOC dashboard.

---

## Features

- **Log ingestion** — parses `auth.log`, `syslog`, and custom JSON security logs
- **8-rule detection engine** — brute force SSH, privilege escalation, sensitive file access, suspicious login time, invalid user enumeration, and more
- **Alert correlation** — groups related alerts into incidents using attack-chain pattern matching
- **ML anomaly scoring** — Isolation Forest trained per-run to flag statistically abnormal sessions
- **Risk scoring** — final 0–100 score per alert and incident with 4 severity bands (Low / Medium / High / Critical)
- **FastAPI REST backend** — full CRUD endpoints for events, alerts, incidents, and dashboard stats
- **JWT authentication** — register/login with bcrypt password hashing; first user auto-assigned admin role
- **Role-based access** — `admin` (full access) and `analyst` (read + update incidents)
- **React SOC dashboard** — Overview, Incidents, Alerts, and Events pages with live filtering
- **Real attack data** — logs collected from a Kali Linux → Ubuntu VM attack simulation (Hydra brute force, nmap, sensitive file access)
- **137 unit tests** — covering correlation, risk scoring, and anomaly scoring modules

---

## Project Structure

```
sentinelai/
├── backend/
│   ├── main.py                  # FastAPI entry point + startup
│   ├── config.py                # Constants: paths, thresholds, severity bands
│   ├── auth.py                  # JWT + bcrypt auth, user CRUD
│   ├── collector.py             # Reads log files, dispatches to parsers
│   ├── parser_auth.py           # Parses /var/log/auth.log
│   ├── parser_syslog.py         # Parses /var/log/syslog
│   ├── parser_custom.py         # Parses custom_security.log (JSON)
│   ├── normalizer.py            # build_event() — common event schema
│   ├── aggregator.py            # Groups events into sessions by IP/user/time
│   ├── detection.py             # 8-rule detection engine
│   ├── correlation.py           # Links alerts into incidents (7 patterns)
│   ├── anomaly_scoring.py       # Isolation Forest ML scoring
│   ├── risk_scoring.py          # Final 0–100 risk score + severity
│   ├── storage.py               # SQLite database layer
│   ├── schemas.py               # Pydantic API models
│   ├── utils.py                 # Shared utilities
│   └── routers/
│       ├── auth.py              # /api/auth — register, login, me, users
│       ├── dashboard.py         # /api/dashboard — summary, charts
│       ├── events.py            # /api/events
│       ├── alerts.py            # /api/alerts
│       └── incidents.py         # /api/incidents
├── frontend/
│   └── dashboard/               # Vite + React + Tailwind CSS
│       └── src/
│           ├── App.jsx          # Routing, auth state, JWT verification
│           ├── api.js           # All API calls with auth headers
│           └── pages/
│               ├── Login.jsx
│               ├── Register.jsx
│               ├── Overview.jsx
│               ├── Incidents.jsx
│               ├── Alerts.jsx
│               └── Events.jsx
├── database/                    # sentinelai.db (auto-created on startup)
├── data/logs/                   # Log files from Ubuntu VM
│   ├── auth.log                 # Real SSH attack logs from Kali→Ubuntu
│   ├── syslog                   # Real system logs from Ubuntu
│   └── custom_security.log      # Custom JSON security events
├── models/                      # Trained Isolation Forest model (.pkl)
├── scripts/
│   ├── run_pipeline.py          # Main pipeline: collect → detect → store
│   └── test_auth.py             # Auth endpoint validation script
└── tests/
    ├── test_correlation.py      # 22 tests
    ├── test_risk_scoring.py     # 28 tests
    └── test_anomaly_scoring.py  # 27 tests
```

---

## Setup

### Prerequisites
- Python 3.10+
- Node.js 18+

### Backend

```bash
# 1. Create and activate virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux/macOS

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the API server
cd backend
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

### Frontend

```bash
cd frontend/dashboard
npm install
npm run dev
# Opens at http://localhost:5173
```

### Ingest logs and populate the dashboard

```bash
# From the project root
python scripts/run_pipeline.py --reset
```

---

## First Run — Creating your admin account

1. Open `http://localhost:5173` and click **Create an account**
2. The **first user registered** is automatically assigned the `admin` role
3. All subsequent registrations become `analyst`

**Email format:** must be `yourname1@sentinelai.com` (letters, dots, ends with a number)

**Password requirements:** 8+ characters, uppercase, number, special character

---

## Running Tests

```bash
python -m pytest tests/ -v
# 137 passed
```

---

## Log Collection from VM

The included `auth.log` and `syslog` were collected from a real Kali→Ubuntu attack simulation:

| Attack | Tool | Log evidence |
|--------|------|-------------|
| SSH brute force | Hydra | 500+ `Failed password` entries from `192.168.56.128` |
| User enumeration | manual SSH loop | `Invalid user` entries for admin, root, oracle, pi, ubuntu |
| Port scan | nmap | Connection events in syslog |
| Successful login + file access | SSH + shell | `Accepted password` + `/etc/passwd` read |

To collect fresh logs from your own VM:

```bash
# On Ubuntu VM — copy logs to a readable location
sudo cp /var/log/auth.log /tmp/auth.log
sudo cp /var/log/syslog /tmp/syslog
sudo chmod 644 /tmp/auth.log /tmp/syslog

# On Kali — SCP to project
scp testuser@<UBUNTU_IP>:/tmp/auth.log data/logs/auth.log
scp testuser@<UBUNTU_IP>:/tmp/syslog   data/logs/syslog

# Re-run pipeline
python scripts/run_pipeline.py --reset
```

---

## Role Permissions

| Feature | Analyst | Admin |
|---------|---------|-------|
| View dashboard, alerts, events, incidents | ✅ | ✅ |
| Update incident status | ✅ | ✅ |
| View all users (`GET /api/auth/users`) | ❌ | ✅ |

---

## Detection Rules

| Rule | Trigger |
|------|---------|
| `brute_force_ssh` | 5+ failed SSH logins from same IP |
| `invalid_user_enumeration` | 3+ invalid user attempts |
| `success_after_failures` | Successful login after multiple failures |
| `sudo_after_suspicious_login` | sudo usage after suspicious login |
| `privilege_after_login` | Privilege escalation post-login |
| `sensitive_file_access` | Access to `/etc/passwd`, `/etc/shadow`, `/root` etc. |
| `suspicious_login_time` | Successful login outside 07:00–20:00 |
| `system_service_anomaly` | Service failures / kernel errors in syslog |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python, FastAPI, SQLite, scikit-learn |
| Auth | JWT (python-jose), bcrypt (passlib) |
| ML | Isolation Forest (sklearn), StandardScaler |
| Frontend | React, Vite, Tailwind CSS, Recharts, Lucide |
| Testing | pytest (137 tests) |
