"""Tests for durable state machine and checkpoint crash recovery."""
import pytest
from api.models import (
    ScanConfig,
    ScanStage,
    ScanState,
    ScanStatus,
)
import db.store as store


@pytest.mark.asyncio
async def test_checkpoint_crud(tmp_path, monkeypatch):
    db_file = tmp_path / "test_checkpoints.db"
    monkeypatch.setenv("CENTRIX_DB_PATH", str(db_file))

    scan_id = "SCN-TEST-CHK"
    config = ScanConfig(target="https://target.example.com", authorized=True)
    state = ScanState(id=scan_id, config=config)
    await store.create_scan(state)

    # Save checkpoint 1: validate
    chk1_id = await store.save_checkpoint(scan_id, ScanStage.validate.value, {"status": "ok", "server": "nginx"})
    assert chk1_id.startswith("chk-")

    # Save checkpoint 2: discover
    chk2_id = await store.save_checkpoint(scan_id, ScanStage.discover.value, {"paths": ["/api/v1", "/login"]})
    assert chk2_id.startswith("chk-")

    # Retrieve latest checkpoint
    latest = await store.get_latest_checkpoint(scan_id)
    assert latest is not None
    assert latest["stage"] == ScanStage.discover.value
    assert "/api/v1" in latest["data"]["paths"]

    # List all checkpoints
    all_cps = await store.list_checkpoints(scan_id)
    assert len(all_cps) == 2
    assert all_cps[0]["stage"] == ScanStage.validate.value
    assert all_cps[1]["stage"] == ScanStage.discover.value

    # Clear checkpoints
    await store.clear_checkpoints(scan_id)
    assert await store.get_latest_checkpoint(scan_id) is None
    assert await store.list_checkpoints(scan_id) == []


@pytest.mark.asyncio
async def test_scan_state_machine_stages():
    # Test all state machine enum values exist
    assert ScanStage.created == "created"
    assert ScanStage.authorization_pending == "authorization_pending"
    assert ScanStage.planning == "planning"
    assert ScanStage.discovering == "discovering"
    assert ScanStage.crawling == "crawling"
    assert ScanStage.browser_testing == "browser_testing"
    assert ScanStage.passive_analysis == "passive_analysis"
    assert ScanStage.active_testing == "active_testing"
    assert ScanStage.validating == "validating"
    assert ScanStage.adjudicating == "adjudicating"
    assert ScanStage.reporting == "reporting"
    assert ScanStage.completed == "completed"
    # Legacy aliases
    assert ScanStage.validate == "validate"
    assert ScanStage.discover == "discover"
    assert ScanStage.crawl == "crawl"
    assert ScanStage.probe == "probe"
    assert ScanStage.analyze == "analyze"
    assert ScanStage.done == "done"


@pytest.mark.asyncio
async def test_engine_resume_from_checkpoint(tmp_path, monkeypatch):
    db_file = tmp_path / "test_engine_resume.db"
    monkeypatch.setenv("CENTRIX_DB_PATH", str(db_file))

    scan_id = "SCN-RESUME-01"
    config = ScanConfig(target="https://target.example.com", authorized=True, safety="passive")
    state = ScanState(id=scan_id, config=config, status=ScanStatus.paused)
    await store.create_scan(state)

    # Pre-populate stage checkpoints up to analyze
    await store.save_checkpoint(scan_id, ScanStage.validate.value, {"status": "ok"})
    await store.save_checkpoint(scan_id, ScanStage.discover.value, {"paths": ["/"]})
    await store.save_checkpoint(scan_id, ScanStage.crawl.value, {"urls": ["https://target.example.com/"], "forms": []})
    await store.save_checkpoint(scan_id, ScanStage.probe.value, {"raw_vulns": []})
    await store.save_checkpoint(scan_id, ScanStage.analyze.value, {"findings": []})

    from scanner.engine import run_scan
    await run_scan(scan_id, config, resume=True)

    final_state = await store.get_scan(scan_id)
    assert final_state is not None
    assert final_state.status == ScanStatus.completed
    assert final_state.can_resume is False

