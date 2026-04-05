"""
routers/alerts.py

GET /api/alerts          — list alerts (paginated, filterable by severity)
GET /api/alerts/{id}     — single alert by ID
"""

import csv
import io
from fastapi import APIRouter, HTTPException, Query, Depends
from fastapi.responses import StreamingResponse
from typing import List, Optional

from storage import get_alerts, count_alerts, get_connection
from schemas import AlertSchema
from auth import get_current_user

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("", response_model=List[AlertSchema])
def list_alerts(
    limit:    int           = Query(100, ge=1, le=500),
    offset:   int           = Query(0,   ge=0),
    severity: Optional[str] = Query(None),
):
    return get_alerts(limit=limit, offset=offset, severity=severity)


@router.get("/count")
def alert_count(severity: Optional[str] = Query(None)):
    return {"count": count_alerts(severity=severity)}


@router.get("/export/csv")
def export_alerts_csv(severity: Optional[str] = Query(None), current_user: dict = Depends(get_current_user)):
    rows = get_alerts(limit=10000, offset=0, severity=severity)
    fields = ["id", "rule_name", "severity", "risk_score", "anomaly_score", "anomaly_level", "description", "created_at"]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=alerts.csv"},
    )


@router.get("/{alert_id}", response_model=AlertSchema)
def get_alert(alert_id: int):
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return dict(row)
