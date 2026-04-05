"""
routers/suppression.py

GET    /api/suppression          — list all suppressed rules
POST   /api/suppression          — suppress a rule
DELETE /api/suppression/{rule}   — unsuppress a rule
GET    /api/notifications        — recent critical/high alerts for bell
"""

from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel
from typing import Optional

from storage import (
    get_suppressed_rules, suppress_rule, unsuppress_rule,
    get_recent_critical_alerts, add_audit_log,
)
from auth import get_current_user

router = APIRouter(tags=["suppression"])


class SuppressRequest(BaseModel):
    rule_name:  str
    reason:     Optional[str] = ""


@router.get("/api/suppression")
def list_suppressed(current_user: dict = Depends(get_current_user)):
    return get_suppressed_rules()


@router.post("/api/suppression", status_code=201)
def suppress(body: SuppressRequest, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    result = suppress_rule(body.rule_name, current_user["username"], body.reason or "")
    add_audit_log(current_user["username"], "rule_suppressed", "alert_rule", None, f"Suppressed {body.rule_name}: {body.reason}")
    return result


@router.delete("/api/suppression/{rule_name}", status_code=200)
def unsuppress(rule_name: str, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    removed = unsuppress_rule(rule_name)
    if not removed:
        raise HTTPException(status_code=404, detail="Rule not suppressed")
    add_audit_log(current_user["username"], "rule_unsuppressed", "alert_rule", None, f"Unsuppressed {rule_name}")
    return {"detail": "Unsuppressed"}


@router.get("/api/notifications")
def notifications(since: str = Query(..., description="ISO timestamp — return alerts after this"), current_user: dict = Depends(get_current_user)):
    return get_recent_critical_alerts(since_iso=since, limit=20)
