"""
main.py

FastAPI application entry point.
Registers all API routers and starts the server.

Run with:
    uvicorn main:app --reload --host 0.0.0.0 --port 8000
"""

import logging
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from utils import setup_logging
from storage import init_db
from routers import events, alerts, incidents, dashboard

setup_logging()
logger = logging.getLogger(__name__)

# Resolve frontend directory (project_root/frontend)
_BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_FRONTEND_DIR = os.path.join(_BASE_DIR, "frontend")

app = FastAPI(
    title="SentinelAI",
    description="Lightweight AI-assisted SIEM prototype",
    version="1.0.0",
)

# Allow browser requests from any origin (dev convenience)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── API routers ──────────────────────────────────────────────
app.include_router(events.router)
app.include_router(alerts.router)
app.include_router(incidents.router)
app.include_router(dashboard.router)


# ── Health check ─────────────────────────────────────────────
@app.get("/health", tags=["system"])
def health_check():
    return {"status": "ok", "service": "SentinelAI", "version": "1.0.0"}


# ── Serve frontend static files ───────────────────────────────
if os.path.isdir(_FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=_FRONTEND_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def serve_dashboard():
        index = os.path.join(_FRONTEND_DIR, "index.html")
        return FileResponse(index)


# ── Startup ──────────────────────────────────────────────────
@app.on_event("startup")
def on_startup():
    logger.info("SentinelAI starting up — initializing database...")
    init_db()
    logger.info("SentinelAI ready.")
