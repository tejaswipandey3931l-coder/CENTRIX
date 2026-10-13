"""Tests for Continuous Retest and Differential Scanning."""
import pytest
from api.models import (
    Finding,
    FindingClassification,
    FindingStatus,
    ScanConfig,
    ScanState,
    Severity,
)
import db.store as store
from scanner.diff import compute_scan_diff


@pytest.mark.asyncio
async def test_compute_scan_diff(tmp_path, monkeypatch):
    db_file = tmp_path / "test_diff.db"
    monkeypatch.setenv("CENTRIX_DB_PATH", str(db_file))

    # Base scan SCN-01
    config_a = ScanConfig(target="https://target.example.com", authorized=True)
    scan_a = ScanState(id="SCN-01", config=config_a)
    await store.create_scan(scan_a)

    f1 = Finding(
        id="VULN-1",
        scan_id="SCN-01",
        title="SQL Injection in ID",
        severity=Severity.high,
        category="sql_injection",
        target="https://target.example.com/api/user",
        parameter="id",
        classification=FindingClassification.confirmed,
        evidence_artifact_ids=["EV-1"],
    )
    f2 = Finding(
        id="VULN-2",
        scan_id="SCN-01",
        title="Missing CSP Header",
        severity=Severity.medium,
        category="missing_security_headers",
        target="https://target.example.com/",
        parameter="",
        classification=FindingClassification.informational,
    )
    await store.add_finding("SCN-01", f1)
    await store.add_finding("SCN-01", f2)

    # Later scan SCN-02 (SQLi resolved, CSP still present, new XSS found)
    scan_b = ScanState(id="SCN-02", config=config_a)
    await store.create_scan(scan_b)

    f2_b = Finding(
        id="VULN-2-B",
        scan_id="SCN-02",
        title="Missing CSP Header",
        severity=Severity.medium,
        category="missing_security_headers",
        target="https://target.example.com/",
        parameter="",
        classification=FindingClassification.informational,
    )
    f3 = Finding(
        id="VULN-3",
        scan_id="SCN-02",
        title="Reflected XSS in search",
        severity=Severity.high,
        category="cross_site_scripting",
        target="https://target.example.com/search",
        parameter="q",
        classification=FindingClassification.confirmed,
        evidence_artifact_ids=["EV-2"],
    )
    await store.add_finding("SCN-02", f2_b)
    await store.add_finding("SCN-02", f3)

    diff = await compute_scan_diff(base_scan_id="SCN-01", target_scan_id="SCN-02")
    assert diff.base_scan_id == "SCN-01"
    assert diff.target_scan_id == "SCN-02"

    # New finding should be XSS (VULN-3)
    assert diff.total_new == 1
    assert diff.new_findings[0].title == "Reflected XSS in search"

    # Resolved finding should be SQLi (VULN-1)
    assert diff.total_resolved == 1

    # Recurrent finding should be Missing CSP Header (VULN-2)
    assert diff.total_recurrent == 1


@pytest.mark.asyncio
async def test_reconcile_scan_findings(tmp_path, monkeypatch):
    """Verify reconcile_scan_findings marks In Review findings as Still Open or Fixed."""
    from pathlib import Path
    from scanner.diff import reconcile_scan_findings

    db_file = tmp_path / "test_reconcile.db"
    monkeypatch.setattr(store, "_db_path", Path(db_file))
    monkeypatch.setattr(store, "_initialized", False)
    store._init_db()

    config = ScanConfig(target="https://target.example.com", authorized=True)
    scan_a = ScanState(id="SCN-ORIG", config=config)
    scan_b = ScanState(id="SCN-RETEST", config=config)
    await store.create_scan(scan_a)
    await store.create_scan(scan_b)

    # Finding 1: In Review and STILL PRESENT in target scan -> should become Still Open
    f1 = Finding(
        id="V-1",
        scan_id="SCN-ORIG",
        title="SQL Injection in login",
        severity=Severity.critical,
        category="sqli",
        vuln_type="sqli",
        target="https://target.example.com/login",
        parameter="user",
        status=FindingStatus.in_review,
        classification=FindingClassification.confirmed,
        evidence="syntax error",
        evidence_artifact_ids=["EV-1"],
    )

    # Finding 2: In Review and NOT in target scan -> should become Fixed
    f2 = Finding(
        id="V-2",
        scan_id="SCN-ORIG",
        title="Reflected XSS in search",
        severity=Severity.high,
        category="xss",
        vuln_type="xss",
        target="https://target.example.com/search",
        parameter="q",
        status=FindingStatus.in_review,
        classification=FindingClassification.confirmed,
        evidence="<script>1</script>",
        evidence_artifact_ids=["EV-2"],
    )

    # Finding 3: Tentative with FP risk not in target scan -> should become Needs Review
    f3 = Finding(
        id="V-3",
        scan_id="SCN-ORIG",
        title="Weak Cipher Suite",
        severity=Severity.low,
        category="crypto",
        target="https://target.example.com/api",
        status=FindingStatus.in_review,
        classification=FindingClassification.tentative,
        why_false_positive_risk="Observation only",
    )

    await store.add_finding("SCN-ORIG", f1)
    await store.add_finding("SCN-ORIG", f2)
    await store.add_finding("SCN-ORIG", f3)

    # Retest scan SCN-RETEST only re-observes SQLi (f1)
    f1_retest = Finding(
        id="V-1-NEW",
        scan_id="SCN-RETEST",
        title="SQL Injection in login",
        severity=Severity.critical,
        category="sqli",
        vuln_type="sqli",
        target="https://target.example.com/login",
        parameter="user",
        status=FindingStatus.open,
        classification=FindingClassification.confirmed,
        evidence="syntax error",
        evidence_artifact_ids=["EV-NEW"],
    )
    await store.add_finding("SCN-RETEST", f1_retest)

    summary = await reconcile_scan_findings("SCN-ORIG", "SCN-RETEST")
    assert summary["still_open"] == 1
    assert summary["fixed"] == 1
    assert summary["needs_review"] == 1

    # Check updated statuses in SQLite store
    upd_f1 = await store.get_finding("V-1")
    assert upd_f1.status == FindingStatus.still_open
    assert upd_f1.reproduction_status == "reproduced"
    assert "[Retest Reconciliation]" in upd_f1.description

    upd_f2 = await store.get_finding("V-2")
    assert upd_f2.status == FindingStatus.fixed
    assert upd_f2.reproduction_status == "remediated"
    assert "[Retest Reconciliation]" in upd_f2.description

    upd_f3 = await store.get_finding("V-3")
    assert upd_f3.status == FindingStatus.needs_review
