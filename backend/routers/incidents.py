"""
routers/incidents.py

GET  /api/incidents          — list incidents (paginated, filterable by status)
GET  /api/incidents/{id}     — single incident by ID
GET  /api/incidents/{id}/events — events linked to an incident
PATCH /api/incidents/{id}/status — update incident status (open/investigating/closed)
"""

import csv
import io
from fastapi import APIRouter, HTTPException, Query, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import List, Optional

import re as _re
from storage import (
    get_incidents, count_incidents,
    get_incident_events, get_connection,
    add_incident_note, get_incident_notes,
    add_audit_log, add_user_notification,
)
from schemas import IncidentSchema, EventSchema
from auth import get_current_user, get_user_by_username

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


class StatusUpdate(BaseModel):
    status: str


@router.get("", response_model=List[IncidentSchema])
def list_incidents(
    limit:  int           = Query(100, ge=1, le=500),
    offset: int           = Query(0,   ge=0),
    status: Optional[str] = Query(None),
):
    return get_incidents(limit=limit, offset=offset, status=status)


@router.get("/count")
def incident_count(status: Optional[str] = Query(None)):
    return {"count": count_incidents(status=status)}


@router.get("/export/csv")
def export_incidents_csv(status: Optional[str] = Query(None), current_user: dict = Depends(get_current_user)):
    rows = get_incidents(limit=10000, offset=0, status=status)
    fields = ["id", "title", "source_ip", "username", "risk_score", "anomaly_level", "status", "assigned_to", "created_at", "description"]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=incidents.csv"},
    )


@router.get("/{incident_id}", response_model=IncidentSchema)
def get_incident(incident_id: int):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return dict(row)


@router.get("/{incident_id}/events", response_model=List[EventSchema])
def get_linked_events(incident_id: int):
    with get_connection() as conn:
        exists = conn.execute(
            "SELECT id FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
    if exists is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return get_incident_events(incident_id)


@router.patch("/{incident_id}/status", response_model=IncidentSchema)
def update_status(incident_id: int, body: StatusUpdate, current_user: dict = Depends(get_current_user)):
    allowed = {"open", "investigating", "closed"}
    if body.status not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status '{body.status}'. Must be one of: {allowed}",
        )
    with get_connection() as conn:
        conn.execute(
            "UPDATE incidents SET status = ? WHERE id = ?",
            (body.status, incident_id),
        )
        row = conn.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    add_audit_log(current_user["username"], "status_change", "incident", incident_id, f"Status → {body.status}")
    return dict(row)


class AssignRequest(BaseModel):
    assigned_to: Optional[str] = None


@router.patch("/{incident_id}/assign", response_model=IncidentSchema)
def assign_incident(incident_id: int, body: AssignRequest, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    with get_connection() as conn:
        conn.execute(
            "UPDATE incidents SET assigned_to = ? WHERE id = ?",
            (body.assigned_to, incident_id),
        )
        row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident = dict(row)
    assignee = body.assigned_to or "unassigned"
    add_audit_log(current_user["username"], "assignment", "incident", incident_id, f"Assigned to {assignee}")
    # Notify the assignee (skip if unassigned or self-assigned)
    if body.assigned_to and body.assigned_to != current_user["username"]:
        if get_user_by_username(body.assigned_to):
            add_user_notification(
                username=body.assigned_to,
                type_="assignment",
                title="Incident assigned to you",
                body=f"{current_user['username']} assigned incident #{incident_id} — {incident['title']}",
                link_id=incident_id,
            )
    return incident


class NoteCreate(BaseModel):
    note: str


@router.get("/{incident_id}/notes")
def list_notes(incident_id: int, current_user: dict = Depends(get_current_user)):
    with get_connection() as conn:
        exists = conn.execute("SELECT id FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if not exists:
        raise HTTPException(status_code=404, detail="Incident not found")
    return get_incident_notes(incident_id)


@router.post("/{incident_id}/notes", status_code=201)
def create_note(incident_id: int, body: NoteCreate, current_user: dict = Depends(get_current_user)):
    if not body.note.strip():
        raise HTTPException(status_code=400, detail="Note cannot be empty")
    with get_connection() as conn:
        exists = conn.execute("SELECT id FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if not exists:
        raise HTTPException(status_code=404, detail="Incident not found")
    note = add_incident_note(incident_id, current_user["username"], body.note.strip())
    add_audit_log(current_user["username"], "note_added", "incident", incident_id, body.note.strip()[:100])
    # Parse @mentions and notify each mentioned user (skip self-mentions)
    mentioned = set(_re.findall(r'@([a-zA-Z0-9_\-]+)', body.note))
    for mention in mentioned:
        if mention == current_user["username"]:
            continue
        if get_user_by_username(mention):
            add_user_notification(
                username=mention,
                type_="mention",
                title=f"@{current_user['username']} mentioned you",
                body=f"In incident #{incident_id}: {body.note.strip()[:120]}",
                link_id=incident_id,
            )
    return note
