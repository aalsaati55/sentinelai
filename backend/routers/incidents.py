"""
routers/incidents.py

GET  /api/incidents          — list incidents (paginated, filterable by status)
GET  /api/incidents/{id}     — single incident by ID
GET  /api/incidents/{id}/events — events linked to an incident
PATCH /api/incidents/{id}/status — update incident status (open/investigating/closed)
"""

from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel
from typing import List, Optional

from storage import (
    get_incidents, count_incidents,
    get_incident_events, get_connection,
    add_incident_note, get_incident_notes,
)
from schemas import IncidentSchema, EventSchema
from auth import get_current_user

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
def update_status(incident_id: int, body: StatusUpdate):
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
    return dict(row)


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
    return add_incident_note(incident_id, current_user["username"], body.note.strip())
