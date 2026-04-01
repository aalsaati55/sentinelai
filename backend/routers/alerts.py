"""
routers/alerts.py

GET /api/alerts          — list alerts (paginated, filterable by severity)
GET /api/alerts/{id}     — single alert by ID
"""

from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional

from storage import get_alerts, count_alerts, get_connection
from schemas import AlertSchema

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


@router.get("/{alert_id}", response_model=AlertSchema)
def get_alert(alert_id: int):
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return dict(row)
