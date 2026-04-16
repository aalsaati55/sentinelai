"""
routers/settings.py

GET  /api/settings/email  — get current email config (admin only)
POST /api/settings/email  — update email config and test connection (admin only)
POST /api/settings/email/test — send a test email
"""

import logging
import os
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional

from auth import get_current_user
from dotenv_utils import save_env_vars

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/settings", tags=["settings"])


class EmailConfig(BaseModel):
    smtp_host:     str
    smtp_port:     int = 587
    smtp_user:     str
    smtp_password: str
    alert_email:   str
    enabled:       bool = True


class EmailConfigOut(BaseModel):
    smtp_host:   str
    smtp_port:   int
    smtp_user:   str
    alert_email: str
    enabled:     bool
    configured:  bool


@router.get("/email", response_model=EmailConfigOut)
def get_email_config(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return {
        "smtp_host":   os.environ.get("SENTINEL_SMTP_HOST", ""),
        "smtp_port":   int(os.environ.get("SENTINEL_SMTP_PORT", "587")),
        "smtp_user":   os.environ.get("SENTINEL_SMTP_USER", ""),
        "alert_email": os.environ.get("SENTINEL_ALERT_EMAIL", ""),
        "enabled":     os.environ.get("SENTINEL_EMAIL_ENABLED", "true").lower() == "true",
        "configured":  bool(
            os.environ.get("SENTINEL_SMTP_HOST") and
            os.environ.get("SENTINEL_SMTP_USER") and
            os.environ.get("SENTINEL_SMTP_PASSWORD") and
            os.environ.get("SENTINEL_ALERT_EMAIL")
        ),
    }


@router.post("/email", response_model=EmailConfigOut)
def update_email_config(body: EmailConfig, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    os.environ["SENTINEL_SMTP_HOST"]     = body.smtp_host
    os.environ["SENTINEL_SMTP_PORT"]     = str(body.smtp_port)
    os.environ["SENTINEL_SMTP_USER"]     = body.smtp_user
    os.environ["SENTINEL_SMTP_PASSWORD"] = body.smtp_password
    os.environ["SENTINEL_ALERT_EMAIL"]   = body.alert_email
    os.environ["SENTINEL_EMAIL_ENABLED"] = "true" if body.enabled else "false"

    # Persist to .env so settings survive backend restarts
    save_env_vars({
        "SENTINEL_SMTP_HOST":     body.smtp_host,
        "SENTINEL_SMTP_PORT":     str(body.smtp_port),
        "SENTINEL_SMTP_USER":     body.smtp_user,
        "SENTINEL_SMTP_PASSWORD": body.smtp_password,
        "SENTINEL_ALERT_EMAIL":   body.alert_email,
        "SENTINEL_EMAIL_ENABLED": "true" if body.enabled else "false",
    })

    # Reload emailer module vars
    import emailer
    emailer.SMTP_HOST     = body.smtp_host
    emailer.SMTP_PORT     = body.smtp_port
    emailer.SMTP_USER     = body.smtp_user
    emailer.SMTP_PASS     = body.smtp_password
    emailer.ALERT_EMAIL   = body.alert_email
    emailer.EMAIL_ENABLED = body.enabled

    logger.info(f"Email config updated and saved to .env by {current_user['username']}")
    return {
        "smtp_host":   body.smtp_host,
        "smtp_port":   body.smtp_port,
        "smtp_user":   body.smtp_user,
        "alert_email": body.alert_email,
        "enabled":     body.enabled,
        "configured":  True,
    }


class ReportConfig(BaseModel):
    enabled: bool = False
    period:  str  = "daily"
    time:    str  = "08:00"
    day:     int  = 0


@router.get("/reports")
def get_report_config(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return {
        "enabled": os.environ.get("SENTINEL_REPORT_ENABLED", "false").lower() == "true",
        "period":  os.environ.get("SENTINEL_REPORT_PERIOD", "daily"),
        "time":    os.environ.get("SENTINEL_REPORT_TIME", "08:00"),
        "day":     int(os.environ.get("SENTINEL_REPORT_DAY", "0")),
    }


@router.post("/reports")
def update_report_config(body: ReportConfig, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    if body.period not in ("daily", "weekly"):
        raise HTTPException(status_code=400, detail="period must be 'daily' or 'weekly'")
    if not (0 <= body.day <= 6):
        raise HTTPException(status_code=400, detail="day must be 0–6")
    try:
        h, m = map(int, body.time.split(":"))
        assert 0 <= h <= 23 and 0 <= m <= 59
    except Exception:
        raise HTTPException(status_code=400, detail="time must be HH:MM (UTC)")

    os.environ["SENTINEL_REPORT_ENABLED"] = "true" if body.enabled else "false"
    os.environ["SENTINEL_REPORT_PERIOD"]  = body.period
    os.environ["SENTINEL_REPORT_TIME"]    = body.time
    os.environ["SENTINEL_REPORT_DAY"]     = str(body.day)

    save_env_vars({
        "SENTINEL_REPORT_ENABLED": "true" if body.enabled else "false",
        "SENTINEL_REPORT_PERIOD":  body.period,
        "SENTINEL_REPORT_TIME":    body.time,
        "SENTINEL_REPORT_DAY":     str(body.day),
    })
    logger.info(f"Report schedule updated by {current_user['username']}: {body}")
    return {"enabled": body.enabled, "period": body.period, "time": body.time, "day": body.day}


@router.post("/reports/send-now")
def send_report_now(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    import emailer
    if not emailer._is_configured():
        raise HTTPException(status_code=400, detail="Email not configured. Set SMTP settings first.")
    period = os.environ.get("SENTINEL_REPORT_PERIOD", "daily")
    try:
        from reporter import send_scheduled_report
        ok = send_scheduled_report(period)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    if not ok:
        raise HTTPException(status_code=500, detail="Failed to send — check server logs.")
    return {"message": f"{period.capitalize()} report sent successfully"}


@router.post("/email/test")
def test_email(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    import emailer
    if not emailer._is_configured():
        raise HTTPException(status_code=400, detail="Email not configured. Set SMTP settings first.")

    try:
        emailer.send_incident_alert({
            "title":       "SentinelAI Test Alert",
            "severity":    "high",
            "risk_score":  75,
            "source_ip":   "192.168.56.128",
            "username":    "testuser",
            "status":      "open",
            "created_at":  "",
            "description": "This is a test alert from SentinelAI to verify email delivery.",
        }, raise_on_error=True)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return {"message": "Test email sent successfully"}
