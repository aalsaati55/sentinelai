"""
routers/events.py

GET /api/events        — list events (paginated, filterable)
GET /api/events/{id}   — single event by ID
"""

from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional

from storage import get_events, count_events
from schemas import EventSchema

router = APIRouter(prefix="/api/events", tags=["events"])


@router.get("", response_model=List[EventSchema])
def list_events(
    limit:      int            = Query(100, ge=1, le=1000),
    offset:     int            = Query(0,   ge=0),
    event_type: Optional[str]  = Query(None),
    source_ip:  Optional[str]  = Query(None),
    log_source: Optional[str]  = Query(None),
):
    return get_events(
        limit=limit,
        offset=offset,
        event_type=event_type,
        source_ip=source_ip,
        log_source=log_source,
    )


@router.get("/count")
def event_count():
    return {"count": count_events()}


@router.get("/types")
def event_types():
    from storage import get_connection
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT DISTINCT event_type FROM events WHERE event_type IS NOT NULL ORDER BY event_type"
        ).fetchall()
    return [r["event_type"] for r in rows]


@router.get("/{event_id}", response_model=EventSchema)
def get_event(event_id: int):
    rows = get_events(limit=1, offset=0)
    # Direct single-row lookup
    from storage import get_connection
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return dict(row)
