"""
emailer.py

Sends email alerts when Critical or High incidents are created.
Configure via environment variables (see below) or a .env file.

Required env vars:
    SENTINEL_SMTP_HOST      — SMTP server (e.g. smtp.gmail.com)
    SENTINEL_SMTP_PORT      — SMTP port (e.g. 587)
    SENTINEL_SMTP_USER      — Sender email address
    SENTINEL_SMTP_PASSWORD  — Sender email password / app password
    SENTINEL_ALERT_EMAIL    — Recipient email address (comma-separated for multiple)

Optional:
    SENTINEL_EMAIL_ENABLED  — Set to "false" to disable emails (default: true)
"""

import os
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional

logger = logging.getLogger(__name__)

SMTP_HOST    = os.environ.get("SENTINEL_SMTP_HOST", "")
SMTP_PORT    = int(os.environ.get("SENTINEL_SMTP_PORT", "587"))
SMTP_USER    = os.environ.get("SENTINEL_SMTP_USER", "")
SMTP_PASS    = os.environ.get("SENTINEL_SMTP_PASSWORD", "")
ALERT_EMAIL  = os.environ.get("SENTINEL_ALERT_EMAIL", "")
EMAIL_ENABLED = os.environ.get("SENTINEL_EMAIL_ENABLED", "true").lower() == "true"

NOTIFY_SEVERITIES = {"critical", "high"}


def _is_configured() -> bool:
    import emailer as _self
    return bool(_self.SMTP_HOST and _self.SMTP_USER and _self.SMTP_PASS and _self.ALERT_EMAIL)


def send_incident_alert(incident: dict, raise_on_error: bool = False) -> bool:
    """
    Send an email alert for a high/critical incident.
    Returns True if sent successfully, False otherwise.
    If raise_on_error is True, raises the SMTP exception instead of swallowing it.
    """
    import emailer as _self

    if not _self.EMAIL_ENABLED:
        return False

    severity = incident.get("severity") or _score_to_severity(incident.get("risk_score", 0))
    if severity not in NOTIFY_SEVERITIES:
        return False

    if not _is_configured():
        logger.warning(
            "Email alert not sent — SMTP not configured. "
            "Set SENTINEL_SMTP_HOST, SENTINEL_SMTP_USER, SENTINEL_SMTP_PASSWORD, SENTINEL_ALERT_EMAIL."
        )
        return False

    recipients = [r.strip() for r in _self.ALERT_EMAIL.split(",") if r.strip()]
    subject = f"[SentinelAI] {severity.upper()} Incident: {incident.get('title', 'Unknown')}"

    body = f"""
SentinelAI Security Alert
==========================

Severity:   {severity.upper()}
Title:      {incident.get('title', '—')}
Risk Score: {incident.get('risk_score', 0)} / 100
Source IP:  {incident.get('source_ip') or '—'}
Username:   {incident.get('username') or '—'}
Status:     {incident.get('status', 'open')}
Created:    {incident.get('created_at', '—')}

Description:
{incident.get('description', '—')}

--
SentinelAI SIEM Prototype
""".strip()

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = _self.SMTP_USER
    msg["To"]      = ", ".join(recipients)
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(_self.SMTP_HOST, _self.SMTP_PORT, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(_self.SMTP_USER, _self.SMTP_PASS)
            server.sendmail(_self.SMTP_USER, recipients, msg.as_string())
        logger.info(f"Email alert sent for incident: {incident.get('title')} → {recipients}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email alert: {e}")
        if raise_on_error:
            raise
        return False


def _score_to_severity(score: int) -> str:
    if score >= 80: return "critical"
    if score >= 60: return "high"
    if score >= 30: return "medium"
    return "low"
