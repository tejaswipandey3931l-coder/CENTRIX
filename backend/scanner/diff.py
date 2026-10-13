"""Differential Scanning and Finding Reconciliation Engine for CENTRIX.

Compares scan runs against the same or related targets to calculate:
- New findings (regressions)
- Resolved findings (fixes)
- Recurrent findings (persistent issues)

Automatically reconciles previous findings:
- Marks persistent findings as 'Still Open'
- Marks resolved findings as 'Fixed'
- Marks ambiguous/weak findings as 'Needs Review'
"""
from __future__ import annotations

from typing import Any, Optional

import db.store as store
from api.models import DifferentialScanResult, Finding, FindingDiffItem, FindingStatus


def _finding_fingerprint(finding: Finding) -> str:
    """Create a canonical identity fingerprint for a finding across scans."""
    cat = (finding.category or finding.vuln_type or "").lower().replace(" ", "_").strip()
    target = (finding.target or "").split("?")[0].rstrip("/").lower().strip()
    param = (finding.parameter or "").lower().strip()
    cwe = (finding.cwe or "").lower().strip()
    return f"{cat}::{target}::{param}::{cwe}"


def match_finding_in_set(target_finding: Finding, candidate_findings: list[Finding]) -> Optional[Finding]:
    """Check if target_finding exists in candidate_findings based on fingerprint or semantic match."""
    target_fp = _finding_fingerprint(target_finding)
    for cand in candidate_findings:
        if _finding_fingerprint(cand) == target_fp:
            return cand

    # Secondary fuzzy match: same target URL + same parameter + matching category/vuln_type
    target_clean = (target_finding.target or "").split("?")[0].rstrip("/").lower()
    target_param = (target_finding.parameter or "").lower().strip()
    target_type = (target_finding.vuln_type or target_finding.category or "").lower()

    for cand in candidate_findings:
        cand_clean = (cand.target or "").split("?")[0].rstrip("/").lower()
        cand_param = (cand.parameter or "").lower().strip()
        cand_type = (cand.vuln_type or cand.category or "").lower()

        if target_clean == cand_clean and target_param == cand_param:
            if target_type in cand_type or cand_type in target_type:
                return cand
            if target_finding.cwe and target_finding.cwe == cand.cwe:
                return cand

    return None


async def compute_scan_diff(base_scan_id: str, target_scan_id: str) -> DifferentialScanResult:
    """Calculate the differential finding set between base_scan_id (earlier) and target_scan_id (later)."""
    base_findings = await store.get_findings(base_scan_id)
    target_findings = await store.get_findings(target_scan_id)

    base_map = {_finding_fingerprint(f): f for f in base_findings}
    target_map = {_finding_fingerprint(f): f for f in target_findings}

    base_keys = set(base_map.keys())
    target_keys = set(target_map.keys())

    new_keys = target_keys - base_keys
    resolved_keys = base_keys - target_keys
    recurrent_keys = target_keys & base_keys

    def _to_diff_item(f: Finding) -> FindingDiffItem:
        return FindingDiffItem(
            finding_id=f.id,
            title=f.title,
            severity=f.severity,
            target=f.target,
            parameter=f.parameter,
            cwe=f.cwe,
        )

    new_items = [_to_diff_item(target_map[k]) for k in sorted(new_keys)]
    resolved_items = [_to_diff_item(base_map[k]) for k in sorted(resolved_keys)]
    recurrent_items = [_to_diff_item(target_map[k]) for k in sorted(recurrent_keys)]

    return DifferentialScanResult(
        base_scan_id=base_scan_id,
        target_scan_id=target_scan_id,
        new_findings=new_items,
        resolved_findings=resolved_items,
        recurrent_findings=recurrent_items,
        total_new=len(new_items),
        total_resolved=len(resolved_items),
        total_recurrent=len(recurrent_items),
    )


async def reconcile_scan_findings(base_scan_id: str, target_scan_id: str) -> dict[str, Any]:
    """Reconcile findings from an earlier base scan against a newer retest scan.

    Updates findings in base_scan_id:
    - If finding was 'In Review', 'Open', or 'Still Open':
      - If matched in target scan -> 'Still Open' (reproduction_status='reproduced')
      - If NOT matched in target scan -> 'Fixed' (reproduction_status='remediated')
    - If finding had tentative/ambiguous evidence -> 'Needs Review'
    """
    base_findings = await store.get_findings(base_scan_id)
    target_findings = await store.get_findings(target_scan_id)

    fixed_count = 0
    still_open_count = 0
    needs_review_count = 0

    for orig_f in base_findings:
        # Reconcile findings that were In Review, Open, or Still Open
        if orig_f.status not in (FindingStatus.in_review, FindingStatus.open, FindingStatus.still_open):
            continue

        matched = match_finding_in_set(orig_f, target_findings)
        if matched:
            orig_f.status = FindingStatus.still_open
            orig_f.reproduction_status = "reproduced"
            orig_f.confidence_reasons.append(f"Vulnerability re-observed during retest scan {target_scan_id}.")
            if "[Retest Reconciliation]" not in orig_f.description:
                orig_f.description += f"\n\n[Retest Reconciliation]: Re-observed in scan {target_scan_id}. Status updated to Still Open."
            still_open_count += 1
        else:
            # Not observed in retest scan
            if str(orig_f.classification.value if hasattr(orig_f.classification, 'value') else orig_f.classification).lower() == "tentative" and orig_f.why_false_positive_risk:
                orig_f.status = FindingStatus.needs_review
                orig_f.reproduction_status = "untested"
                orig_f.confidence_reasons.append(f"Not re-observed in scan {target_scan_id}; marked Needs Review due to tentative baseline.")
                needs_review_count += 1
            else:
                orig_f.status = FindingStatus.fixed
                orig_f.reproduction_status = "remediated"
                orig_f.confidence_reasons.append(f"Verified resolved in retest scan {target_scan_id}.")
                if "[Retest Reconciliation]" not in orig_f.description:
                    orig_f.description += f"\n\n[Retest Reconciliation]: Remediated. No longer observed in scan {target_scan_id}."
                fixed_count += 1

        await store.update_finding(orig_f)

    return {
        "base_scan_id": base_scan_id,
        "target_scan_id": target_scan_id,
        "fixed": fixed_count,
        "still_open": still_open_count,
        "needs_review": needs_review_count,
    }
