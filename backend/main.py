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
from auth import init_users_table
from dotenv_utils import load_env

# Load .env before anything else so SMTP vars are available at import time
load_env()
from routers import events, alerts, incidents, dashboard
from routers import auth as auth_router
from routers import live as live_router
from routers import settings as settings_router
from routers import audit as audit_router
from routers import suppression as suppression_router
from routers import geoip as geoip_router
from routers.watchlist import router as watchlist_router, playbook_router, soar_router
from routers.threatintel import router as threatintel_router
from routers import soar_execute as soar_execute_router

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
app.include_router(auth_router.router)
app.include_router(events.router)
app.include_router(alerts.router)
app.include_router(incidents.router)
app.include_router(dashboard.router)
app.include_router(live_router.router)
app.include_router(settings_router.router)
app.include_router(audit_router.router)
app.include_router(suppression_router.router)
app.include_router(geoip_router.router)
app.include_router(watchlist_router)
app.include_router(playbook_router)
app.include_router(soar_router)
app.include_router(soar_execute_router.router)
app.include_router(threatintel_router)


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
    init_users_table()
    # Re-apply .env into emailer module vars (in case emailer was imported before load_env)
    import emailer
    import os
    emailer.SMTP_HOST     = os.environ.get("SENTINEL_SMTP_HOST", "")
    emailer.SMTP_PORT     = int(os.environ.get("SENTINEL_SMTP_PORT", "587"))
    emailer.SMTP_USER     = os.environ.get("SENTINEL_SMTP_USER", "")
    emailer.SMTP_PASS     = os.environ.get("SENTINEL_SMTP_PASSWORD", "")
    emailer.ALERT_EMAIL   = os.environ.get("SENTINEL_ALERT_EMAIL", "")
    emailer.EMAIL_ENABLED = os.environ.get("SENTINEL_EMAIL_ENABLED", "true").lower() == "true"
    logger.info("SentinelAI ready.")
