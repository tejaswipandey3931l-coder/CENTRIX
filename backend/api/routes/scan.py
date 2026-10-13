"""
Scan routes:
  POST   /api/scan/start          → launch a new scan (background task)
  GET    /api/scan/{id}/status    → O(1) status lookup
  POST   /api/scan/{id}/pause     → toggle pause
  POST   /api/scan/{id}/stop      → stop scan
  GET    /api/scans               → list all scans
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, HTTPException

import db.store as store
from api.models import (
    ScanConfig,
    ScanState,
    ScanStatus,
    ScanStage,
    StartScanResponse,
    ScanStatusResponse,
)
from scanner.engine import run_scan
from scanner.safety import TargetSafetyError, ensure_public_target, normalise_target

router = APIRouter(prefix="/api/scan", tags=["scan"])


@router.post("/start", response_model=StartScanResponse)
async def start_scan(config: ScanConfig, bg: BackgroundTasks):
    if not config.authorized:
        raise HTTPException(
            status_code=422,
            detail="Confirm that you are authorized to scan this target before starting.",
        )
    try:
        config.target = normalise_target(config.target)
        await ensure_public_target(config.target)
    except TargetSafetyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    scan_id = f"SCN-{uuid.uuid4().hex[:8].upper()}"
    state = ScanState(
        id=scan_id,
        config=config,
        status=ScanStatus.pending,
        stage=ScanStage.validate,
        progress=0,
        started_at=datetime.utcnow(),
    )
    await store.create_scan(state)

    # Launch scanner as a background asyncio task
    bg.add_task(_run_in_background, scan_id, config)

    return StartScanResponse(
        scan_id=scan_id,
        status=ScanStatus.pending,
        message=f"Scan {scan_id} queued — target: {config.target}",
    )


async def _run_in_background(scan_id: str, config: ScanConfig, resume: bool = False):
    """Wrapper so background_task errors are caught and stored."""
    try:
        await run_scan(scan_id, config, resume=resume)
    except Exception as exc:
        state = await store.get_scan(scan_id)
        if state:
            state.status = ScanStatus.error
            state.error_msg = str(exc)
            state.finished_at = datetime.utcnow()
            await store.update_scan(state)
        await store.push_log(scan_id, f"[ERROR] Scan crashed: {exc}")


@router.get("/{scan_id}/status", response_model=ScanStatusResponse)
async def scan_status(scan_id: str):
    state = await store.get_scan(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    dur = None
    if state.started_at and state.finished_at:
        dur = (state.finished_at - state.started_at).total_seconds()
    return ScanStatusResponse(
        scan_id=state.id,
        status=state.status,
        stage=state.stage,
        progress=state.progress,
        findings_count=state.findings_count,
        requests_sent=state.requests_sent,
        urls_discovered=state.urls_discovered,
        started_at=state.started_at,
        finished_at=state.finished_at,
        duration_s=dur,
        checkpoint_stage=state.checkpoint_stage,
        can_resume=state.can_resume,
    )


@router.post("/{scan_id}/pause")
async def pause_scan(scan_id: str):
    state = await store.get_scan(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    if state.status == ScanStatus.running:
        state.status = ScanStatus.paused
    elif state.status == ScanStatus.paused:
        state.status = ScanStatus.running
    await store.update_scan(state)
    return {"scan_id": scan_id, "status": state.status}


@router.post("/{scan_id}/resume")
async def resume_scan(scan_id: str, bg: BackgroundTasks):
    state = await store.get_scan(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    if state.status == ScanStatus.running:
        return {"scan_id": scan_id, "status": state.status, "message": "Scan is already running"}

    state.status = ScanStatus.running
    await store.update_scan(state)
    await store.push_log(scan_id, f"[INFO] Resuming scan {scan_id} from saved checkpoints...")
    bg.add_task(_run_in_background, scan_id, state.config, resume=True)
    return {"scan_id": scan_id, "status": state.status, "message": "Scan resumed"}


@router.get("/{scan_id}/checkpoints")
async def get_checkpoints(scan_id: str):
    state = await store.get_scan(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    checkpoints = await store.list_checkpoints(scan_id)
    return {"scan_id": scan_id, "checkpoints": checkpoints}


@router.get("/{scan_id}/diff/{previous_scan_id}")
async def diff_scans(scan_id: str, previous_scan_id: str):
    base = await store.get_scan(previous_scan_id)
    target = await store.get_scan(scan_id)
    if not base or not target:
        raise HTTPException(status_code=404, detail="One or both scans not found")
    from scanner.diff import compute_scan_diff
    return await compute_scan_diff(base_scan_id=previous_scan_id, target_scan_id=scan_id)


@router.post("/{scan_id}/stop")
async def stop_scan(scan_id: str):
    state = await store.get_scan(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    state.status = ScanStatus.stopped
    state.finished_at = datetime.utcnow()
    await store.update_scan(state)
    await store.push_log(scan_id, "[INFO] Scan stopped by user.")
    return {"scan_id": scan_id, "status": "stopped"}


@router.get("s")
async def list_scans():
    scans = await store.list_scans()
    return [
        {
            "id": s.id,
            "target": s.config.target,
            "profile": s.config.profile,
            "status": s.status,
            "progress": s.progress,
            "findings_count": s.findings_count,
            "started_at": s.started_at,
        }
        for s in scans
    ]

