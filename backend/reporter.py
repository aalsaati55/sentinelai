"""
reporter.py

Builds and sends a scheduled HTML security report email.
Called by scheduler.py on the configured daily/weekly schedule.
"""

import logging
import smtplib
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)


# ── Colour helpers ────────────────────────────────────────────────────────────

def _sev_color(sev):
    return {"critical": "#f85149", "high": "#f0883e", "medium": "#e3b341", "low": "#3fb950"}.get(
        (sev or "").lower(), "#8b949e"
    )

def _status_color(s):
    return {"open": "#f85149", "investigating": "#f0883e", "closed": "#3fb950"}.get(
        (s or "").lower(), "#8b949e"
    )

def _badge(text, color):
    return (
        f'<span style="background:{color}22;color:{color};border:1px solid {color}44;'
        f'border-radius:9999px;padding:2px 10px;font-size:11px;font-weight:600">{text.upper()}</span>'
    )

def _th(*cols):
    td = "".join(
        f'<th style="background:#161b22;color:#8b949e;text-transform:uppercase;font-size:11px;'
        f'letter-spacing:.05em;padding:8px 12px;text-align:left;border-bottom:1px solid #30363d">{c}</th>'
        for c in cols
    )
    return f"<tr>{td}</tr>"

def _tr(*cols):
    td = "".join(
        f'<td style="color:#c9d1d9;font-size:13px;padding:10px 12px;text-align:left;'
        f'border-bottom:1px solid #21262d">{c}</td>'
        for c in cols
    )
    return f"<tr>{td}</tr>"

def _table(header_row, body_rows):
    return (
        f'<table style="width:100%;border-collapse:collapse;margin-top:12px">'
        f'{header_row}{"".join(body_rows)}</table>'
    )

def _section(title, content):
    return (
        f'<div style="background:#0d1117;border:1px solid #30363d;border-radius:12px;'
        f'padding:20px 24px;margin-bottom:20px">'
        f'<h3 style="margin:0 0 12px 0;font-size:13px;font-weight:600;text-transform:uppercase;'
        f'letter-spacing:.05em;color:#8b949e">{title}</h3>'
        f'{content}</div>'
    )

def _card(label, value, color="#58a6ff"):
    return (
        f'<div style="background:#1c2128;border:1px solid #30363d;border-radius:10px;'
        f'padding:18px 22px;flex:1;min-width:110px">'
        f'<div style="font-size:28px;font-weight:700;color:{color}">{value}</div>'
        f'<div style="font-size:12px;color:#8b949e;margin-top:4px">{label}</div></div>'
    )


# ── Data gathering ────────────────────────────────────────────────────────────

def _gather(since_iso):
    from storage import get_connection
    with get_connection() as conn:
        total_alerts = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE created_at >= ?", (since_iso,)
        ).fetchone()[0]

        sev_rows = conn.execute(
            "SELECT severity, COUNT(*) c FROM alerts WHERE created_at >= ? GROUP BY severity",
            (since_iso,)
        ).fetchall()
        by_sev = {r["severity"]: r["c"] for r in sev_rows}

        total_inc = conn.execute(
            "SELECT COUNT(*) FROM incidents WHERE created_at >= ?", (since_iso,)
        ).fetchone()[0]

        open_inc = conn.execute(
            "SELECT COUNT(*) FROM incidents WHERE created_at >= ? AND status='open'", (since_iso,)
        ).fetchone()[0]

        closed_inc = conn.execute(
            "SELECT COUNT(*) FROM incidents WHERE status='closed' AND created_at >= ?", (since_iso,)
        ).fetchone()[0]

        inc_rows = conn.execute(
            """SELECT title,anomaly_level AS severity,status,source_ip,risk_score FROM incidents
               WHERE created_at >= ? ORDER BY risk_score DESC LIMIT 5""", (since_iso,)
        ).fetchall()

        alert_rows = conn.execute(
            """SELECT rule_name,severity,source_ip,risk_score FROM alerts
               WHERE created_at >= ? AND severity IN ('critical','high')
               ORDER BY risk_score DESC LIMIT 5""", (since_iso,)
        ).fetchall()

        ip_rows = conn.execute(
            """SELECT source_ip, COUNT(*) cnt FROM alerts
               WHERE created_at >= ? AND source_ip IS NOT NULL
               GROUP BY source_ip ORDER BY cnt DESC LIMIT 5""", (since_iso,)
        ).fetchall()

        team_rows = conn.execute(
            """SELECT username, COUNT(*) closed FROM audit_log
               WHERE action='status_change' AND detail LIKE '%closed%' AND created_at >= ?
               GROUP BY username ORDER BY closed DESC LIMIT 5""", (since_iso,)
        ).fetchall()

    return {
        "total_alerts": total_alerts, "by_sev": by_sev,
        "total_inc": total_inc, "open_inc": open_inc, "closed_inc": closed_inc,
        "incidents":  [dict(r) for r in inc_rows],
        "top_alerts": [dict(r) for r in alert_rows],
        "top_ips":    [dict(r) for r in ip_rows],
        "team":       [dict(r) for r in team_rows],
    }


# ── HTML builder ──────────────────────────────────────────────────────────────

def build_html_report(period, since_iso, now_iso):
    d = _gather(since_iso)
    label   = "Daily" if period == "daily" else "Weekly"
    window  = "last 24 hours" if period == "daily" else "last 7 days"
    ts      = now_iso[:19].replace("T", " ")

    # Stat cards
    cards = "".join([
        _card("Total Alerts",  d["total_alerts"],           "#58a6ff"),
        _card("Critical",      d["by_sev"].get("critical",0),"#f85149"),
        _card("High",          d["by_sev"].get("high",0),   "#f0883e"),
        _card("New Incidents", d["total_inc"],               "#e3b341"),
        _card("Still Open",    d["open_inc"],                "#f85149"),
        _card("Closed",        d["closed_inc"],              "#3fb950"),
    ])

    # Incidents table
    if d["incidents"]:
        inc_content = _table(
            _th("Title", "Severity", "Status", "Source IP", "Risk"),
            [_tr(
                f'<span style="color:#c9d1d9">{r["title"][:55]}</span>',
                _badge(r["severity"] or "—", _sev_color(r["severity"])),
                _badge(r["status"] or "—",   _status_color(r["status"])),
                f'<code style="color:#79c0ff;font-size:12px">{r["source_ip"] or "—"}</code>',
                f'<b style="color:#e3b341">{r["risk_score"]}</b>',
            ) for r in d["incidents"]]
        )
    else:
        inc_content = '<p style="color:#8b949e;font-size:13px">No incidents in this period.</p>'

    # High/Critical alerts table
    if d["top_alerts"]:
        al_content = _table(
            _th("Rule", "Severity", "Source IP", "Risk"),
            [_tr(
                f'<span style="color:#c9d1d9">{r["rule_name"]}</span>',
                _badge(r["severity"] or "—", _sev_color(r["severity"])),
                f'<code style="color:#79c0ff;font-size:12px">{r["source_ip"] or "—"}</code>',
                f'<b style="color:#e3b341">{r["risk_score"]}</b>',
            ) for r in d["top_alerts"]]
        )
    else:
        al_content = '<p style="color:#8b949e;font-size:13px">No critical/high alerts in this period.</p>'

    # Top IPs
    if d["top_ips"]:
        ip_content = _table(
            _th("Source IP", "Alert Count"),
            [_tr(
                f'<code style="color:#79c0ff;font-size:12px">{r["source_ip"]}</code>',
                f'<b style="color:#c9d1d9">{r["cnt"]}</b>',
            ) for r in d["top_ips"]]
        )
    else:
        ip_content = '<p style="color:#8b949e;font-size:13px">No alert activity in this period.</p>'

    # Team activity
    if d["team"]:
        tm_content = _table(
            _th("Analyst", "Incidents Closed"),
            [_tr(
                f'<span style="color:#79c0ff;font-weight:600">{r["username"]}</span>',
                f'<b style="color:#3fb950">{r["closed"]}</b>',
            ) for r in d["team"]]
        )
    else:
        tm_content = '<p style="color:#8b949e;font-size:13px">No incidents closed in this period.</p>'

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0d1117;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">
<div style="max-width:700px;margin:32px auto;padding:0 16px">

  <div style="background:#161b22;border:1px solid #30363d;border-radius:12px;padding:24px 28px;margin-bottom:20px">
    <h1 style="margin:0;font-size:20px;font-weight:700;color:#f0f6fc">🛡️ SentinelAI — {label} Security Report</h1>
    <p style="margin:6px 0 0;font-size:13px;color:#8b949e">Generated {ts} UTC &nbsp;·&nbsp; Period: {window}</p>
  </div>

  <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px">{cards}</div>

  {_section("Top Incidents", inc_content)}
  {_section("Critical &amp; High Alerts", al_content)}
  {_section("Top Attacking IPs", ip_content)}
  {_section("Team Activity — Incidents Closed", tm_content)}

  <div style="text-align:center;padding:20px 0;color:#484f58;font-size:12px">
    SentinelAI SIEM Prototype &nbsp;·&nbsp; Automated {label} Report
  </div>
</div>
</body></html>"""


# ── Send ──────────────────────────────────────────────────────────────────────

def send_scheduled_report(period):
    """Build and email the scheduled report. Returns True on success."""
    import emailer
    if not emailer.EMAIL_ENABLED:
        logger.info("Scheduled report skipped — email disabled.")
        return False
    if not emailer._is_configured():
        logger.warning("Scheduled report skipped — SMTP not configured.")
        return False

    now      = datetime.now(timezone.utc)
    delta    = timedelta(days=1) if period == "daily" else timedelta(days=7)
    since    = now - delta
    since_iso = since.strftime("%Y-%m-%dT%H:%M:%S")
    now_iso   = now.strftime("%Y-%m-%dT%H:%M:%S")

    label     = "Daily" if period == "daily" else "Weekly"
    subject   = f"[SentinelAI] {label} Security Report — {now.strftime('%Y-%m-%d')}"
    html      = build_html_report(period, since_iso, now_iso)
    recipients = [r.strip() for r in emailer.ALERT_EMAIL.split(",") if r.strip()]

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = emailer.SMTP_USER
    msg["To"]      = ", ".join(recipients)
    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP(emailer.SMTP_HOST, emailer.SMTP_PORT, timeout=20) as srv:
            srv.ehlo(); srv.starttls(); srv.ehlo()
            srv.login(emailer.SMTP_USER, emailer.SMTP_PASS)
            srv.sendmail(emailer.SMTP_USER, recipients, msg.as_string())
        logger.info(f"Scheduled {label} report sent to {recipients}")
        return True
    except Exception as e:
        logger.error(f"Failed to send scheduled report: {e}")
        return False
