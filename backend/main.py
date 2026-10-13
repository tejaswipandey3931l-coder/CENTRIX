"""
VulnGuard Backend — FastAPI Application Entry Point

Starts the server with:
  uvicorn main:app --reload --port 8000
"""
from __future__ import annotations

import asyncio

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import scan, findings, reports, ws, manual, imports, evidence, integrations, proof, authz, oob, schedules, agent

app = FastAPI(
    title="VulnGuard API",
    description="Vulnerability Scanner Backend",
    version="4.0.0",
)

# ── CORS — allow the Vite dev server (port 8443 default, also 5173) ──────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:8443",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8443",
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(scan.router)
app.include_router(findings.router)
app.include_router(reports.router)
app.include_router(ws.router)
app.include_router(manual.router)
app.include_router(imports.router)
app.include_router(evidence.router)
app.include_router(integrations.router)
app.include_router(proof.router)
app.include_router(authz.router)
app.include_router(oob.router)
app.include_router(schedules.router)
app.include_router(agent.router)


try:
    from fastapi.middleware.wsgi import WSGIMiddleware
    from flask import Flask
    from scanner.threat_intel.routes import threat_intel_bp

    threat_intel_flask_app = Flask("threat_intel")
    threat_intel_flask_app.register_blueprint(threat_intel_bp)

    class ThreatIntelWSGIApp:
        def __init__(self, app):
            self.app = app

        def __call__(self, environ, start_response):
            path = environ.get("PATH_INFO", "")
            if not path.startswith("/api/threat-intel"):
                environ["PATH_INFO"] = "/api/threat-intel" + path
            return self.app(environ, start_response)

    app.mount("/api/threat-intel", WSGIMiddleware(ThreatIntelWSGIApp(threat_intel_flask_app)))
except ImportError as err:
    print(f"[WARN] Threat Intel Flask routes not mounted: {err}")


@app.on_event("startup")
async def start_local_scheduler():
    asyncio.create_task(schedules.scheduler_loop())
    try:
        from scanner.threat_intel.config import cfg
        from scanner.threat_intel.sync_worker import start_scheduler
        if cfg.sync_on_startup:
            start_scheduler()
    except Exception as exc:
        print(f"[WARN] Could not start threat intel scheduler: {exc}")

    # Cleanup orphaned scans left in pending/running state from a previous server run.
    # Without this, every restart leaves "ghost" scans that the frontend picks up as active.
    try:
        import db.store as store
        from api.models import ScanStatus
        from datetime import datetime
        all_scans = await store.list_scans()
        cleaned = 0
        for scan in all_scans:
            if scan.status in (ScanStatus.pending, ScanStatus.running):
                scan.status = ScanStatus.stopped
                scan.error_msg = "Scan interrupted by server restart"
                scan.finished_at = datetime.utcnow()
                await store.update_scan(scan)
                cleaned += 1
        if cleaned:
            print(f"[STARTUP] Marked {cleaned} orphaned scan(s) as stopped (server restart)")
    except Exception as exc:
        print(f"[WARN] Startup scan cleanup failed: {exc}")


@app.get("/")
async def root():
    return {
        "name": "VulnGuard API",
        "version": "4.0.0",
        "status": "operational",
        "docs": "/docs",
    }


@app.get("/health")
async def health():
    return {"status": "ok"}
