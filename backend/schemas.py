"""
schemas.py

Pydantic models for API request/response validation.
Used by FastAPI endpoints.

Placeholder — full implementation in Week 1 (Day 5) alongside storage.py.
"""

from pydantic import BaseModel
from typing import Optional


class EventSchema(BaseModel):
    id:         Optional[int] = None
    timestamp:  str
    log_source: str
    event_type: str
    source_ip:  Optional[str] = None
    username:   Optional[str] = None
    hostname:   Optional[str] = None
    status:     str
    message:    str
    raw_log:    str

    class Config:
        from_attributes = True


class AlertSchema(BaseModel):
    id:                Optional[int]  = None
    event_id:          Optional[int]  = None
    rule_name:         str
    severity:          str
    risk_score:        int
    anomaly_score:     Optional[float] = None
    anomaly_level:     Optional[str]   = None
    description:       str
    mitre_techniques:  Optional[list]  = []
    source_ip:         Optional[str]   = None
    username:          Optional[str]   = None
    created_at:        Optional[str]   = None
    false_positive:    Optional[int]   = 0
    fp_reason:         Optional[str]   = None

    class Config:
        from_attributes = True


class IncidentSchema(BaseModel):
    id:            Optional[int] = None
    title:         str
    description:   str
    source_ip:     Optional[str] = None
    username:      Optional[str] = None
    risk_score:    int
    anomaly_level: Optional[str] = None
    status:        str = "open"
    assigned_to:   Optional[str] = None
    created_at:    Optional[str] = None
    note_count:    Optional[int] = 0
    false_positive: Optional[int] = 0
    fp_reason:      Optional[str] = None

    class Config:
        from_attributes = True
