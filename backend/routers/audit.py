"""
routers/audit.py

GET /api/audit         — list audit log entries (admin only)
GET /api/audit/export/csv — download audit log as CSV
"""

import csv
import io
from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse

from storage import get_audit_log
from auth import get_current_user

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("")
def list_audit_log(
    limit:  int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user),
):
    return get_audit_log(limit=limit, offset=offset)


@router.get("/export/csv")
def export_audit_csv(current_user: dict = Depends(get_current_user)):
    rows = get_audit_log(limit=10000, offset=0)
    fields = ["id", "username", "action", "target_type", "target_id", "detail", "created_at"]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_log.csv"},
    )
