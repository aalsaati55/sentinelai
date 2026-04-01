"""
main.py

FastAPI application entry point.
Registers all API routers and starts the server.

Placeholder — full endpoints implemented in Week 5.
"""

import logging
from fastapi import FastAPI

from utils import setup_logging
from storage import init_db

setup_logging()
logger = logging.getLogger(__name__)

app = FastAPI(
    title="SentinelAI",
    description="Lightweight AI-assisted SIEM prototype",
    version="0.1.0",
)


@app.on_event("startup")
def on_startup():
    logger.info("SentinelAI starting up...")
    init_db()


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "SentinelAI"}


# TODO: Register routers in Week 5
# from routers import events, alerts, incidents, dashboard
# app.include_router(events.router)
# app.include_router(alerts.router)
# app.include_router(incidents.router)
# app.include_router(dashboard.router)
