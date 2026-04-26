# SentinelAI — Frontend Dashboard

React + Vite + Tailwind CSS SOC dashboard for the SentinelAI SIEM platform.

## Stack

- **React 18** — component-based UI
- **Vite** — dev server with HMR
- **Tailwind CSS** — utility-first styling with dark theme design system
- **Recharts** — bar, line, area, and pie charts for analytics panels
- **Lucide Icons** — icon library
- **WebSocket** — live event/alert feed with auto-reconnect

## Pages

| Page | Route | Description |
|------|-------|-------------|
| Login | `/` | JWT login with optional TOTP MFA step |
| Register | `/register` | Account creation (first user → admin) |
| Overview | `overview` | KPI cards, live feed, charts, team activity |
| Incidents | `incidents` | Correlated incidents with SOAR, playbook, notes |
| Alerts | `alerts` | Rule-based alerts with MITRE tags, GeoIP, FP marking |
| Alert Tuning | `alert-tuning` | Threshold tuning and rule suppression (admin) |
| Events | `events` | Raw normalized log events |
| Attack Map | `attack-map` | Live SVG world map with attacker IPs |
| Watchlist | `watchlist` | Monitored IP management |
| Audit Log | `audit-log` | Full activity audit trail with filtered CSV export |
| Users | `users` | User management (admin) |
| Settings | `settings` | Email alerts, SSH config, MFA, password, reports |

## Development

```bash
npm install
npm run dev
# Runs at http://localhost:5173
# Backend must be running at http://localhost:8000
```

## Key Components

- **`LiveFeed.jsx`** — WebSocket live event/alert stream with severity filter, scrolls within its panel
- **`NotificationBell.jsx`** — Notification dropdown rendered via React portal to always appear above all page content
- **`Panel.jsx`** — Reusable card; auto-enables scrollable flex layout when given a fixed height class (e.g. `h-80`)
- **`AttackMap.jsx`** — SVG world map from local GeoJSON with zoom/pan and threat intel markers
- **`OnboardingModal.jsx`** — 8-step first-login tour

## CSV Export

All four data pages export **only the currently filtered rows**, not the full dataset:
- **Alerts** — respects severity, rule, FP, and search filters
- **Incidents** — respects status, severity, FP, and search filters
- **Events** — respects source, type, status, and IP filters
- **Audit Log** — respects user and action filters
