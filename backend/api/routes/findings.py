"""
Findings routes:
  GET /api/findings              → all findings (optionally filter by scan_id)
  GET /api/findings/{id}         → single finding O(1) after flattening
"""
from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Query, HTTPException, BackgroundTasks
import db.store as store
from api.models import Finding, FindingStatus, FindingStatusUpdate, ScanProfile, ScanStage, ScanState, ScanStatus
from scanner.engine import run_scan
from scanner.safety import TargetSafetyError, ensure_public_target

router = APIRouter(prefix="/api/findings", tags=["findings"])

# O(1) finding lookup built lazily — rebuilt when new findings arrive
_finding_index: dict[str, Finding] = {}


def _index_finding(f: Finding):
    _finding_index[f.id] = f


@router.get("")
async def list_findings(scan_id: str | None = Query(default=None)):
    if scan_id:
        findings = await store.get_findings(scan_id)
    else:
        findings = await store.get_all_findings()

    return [
        {
            "id": f.id,
            "scan_id": f.scan_id,
            "title": f.title,
            "severity": f.severity,
            "category": f.category,
            "target": f.target,
            "parameter": f.parameter,
            "confidence": f.confidence,
            "status": f.status,
            "found_at": f.found_at,
            "cwe": f.cwe,
            "cvss": f.cvss,
        }
        for f in findings
    ]


@router.get("/{finding_id}")
async def get_finding(finding_id: str):
    # Try O(1) index first
    f = _finding_index.get(finding_id)
    if f:
        return f.model_dump()

    # Fall back: linear scan once (then index it)
    all_findings = await store.get_all_findings()
    for finding in all_findings:
        _finding_index[finding.id] = finding
        if finding.id == finding_id:
            return finding.model_dump()

    raise HTTPException(status_code=404, detail="Finding not found")


@router.patch("/{finding_id}/status")
async def update_finding_status(finding_id: str, payload: FindingStatusUpdate):
    finding = await store.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding.status = payload.status
    await store.update_finding(finding)
    _index_finding(finding)
    return finding.model_dump(mode="json")


@router.post("/{finding_id}/retest")
async def retest_finding(finding_id: str, bg: BackgroundTasks):
    finding = await store.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    original_scan = await store.get_scan(finding.scan_id)
    if not original_scan:
        raise HTTPException(status_code=404, detail="Original scan not found")
    if not original_scan.config.authorized:
        raise HTTPException(status_code=403, detail="Original scan was not authorized for retesting")
    try:
        await ensure_public_target(finding.target)
    except TargetSafetyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    config = original_scan.config.model_copy(deep=True)
    config.target = finding.target
    config.imported_urls = [finding.target]
    config.profile = ScanProfile.quick
    config.max_requests = min(config.max_requests, 120)
    config.depth = min(config.depth, 2)
    config.retest_finding_id = finding_id
    config.base_scan_id = original_scan.id

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
    await store.push_log(scan_id, f"[INFO] Retest queued for finding {finding_id}")
    bg.add_task(run_scan, scan_id, config)
    finding.status = FindingStatus.in_review
    await store.update_finding(finding)
    _index_finding(finding)
    return {"scan_id": scan_id, "finding_id": finding_id, "status": "queued"}
