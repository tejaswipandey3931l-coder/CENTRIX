"""Report routes for Centrix exports."""
from __future__ import annotations

import base64
import json
import uuid
from datetime import datetime
from html import escape
from xml.sax.saxutils import escape as xml_escape

from fastapi import APIRouter, BackgroundTasks, HTTPException, Response

import db.store as store
from api.models import Report, ReportConfig
from reporting.pdf_report import build_centrix_pdf_report
from reporting.github_issues import build_github_issues_bundle
from reporting.jira import build_jira_export_bundle

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.post("/generate")
async def generate_report(cfg: ReportConfig, bg: BackgroundTasks):
    state = await store.get_scan(cfg.scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")

    report_id = f"RPT-{uuid.uuid4().hex[:8].upper()}"
    findings = await store.get_findings(cfg.scan_id)
    evidence = await store.get_evidence(cfg.scan_id)

    report = Report(
        id=report_id,
        scan_id=cfg.scan_id,
        name=f"Centrix {cfg.report_type.capitalize()} Report - {cfg.target_scope or state.config.target}",
        report_type=cfg.report_type,
        target=cfg.target_scope or state.config.target,
        generated_at=datetime.utcnow(),
        status="Ready",
        findings_count=len(findings),
        size="0.0 KB",
        format=cfg.format,
    )

    if cfg.format == "json":
        report.content = _build_json_report(report_id, state, findings)
    elif cfg.format == "html":
        report.content = _build_html_report(report_id, state, findings)
    elif cfg.format == "sarif":
        report.content = _build_sarif_report(report_id, state, findings)
    elif cfg.format == "junit":
        report.content = _build_junit_report(report_id, state, findings)
    elif cfg.format == "evidence":
        report.content = _build_evidence_bundle(report_id, state, findings, evidence)
    elif cfg.format == "github_issues":
        report.content = build_github_issues_bundle(state, findings)
    elif cfg.format == "jira":
        report.content = build_jira_export_bundle(state, findings)
    elif cfg.format == "pdf":
        try:
            pdf_bytes = build_centrix_pdf_report(report_id, state, findings, evidence)
            report.content = base64.b64encode(pdf_bytes).decode("ascii")
            report.size = f"{max(1, len(pdf_bytes)) / 1024:.1f} KB"
        except RuntimeError as err:
            # Fallback to HTML report if reportlab is not installed
            report.content = _build_html_report(report_id, state, findings)
            report.format = "html"
            report.size = f"{max(1, len((report.content or '').encode('utf-8'))) / 1024:.1f} KB"

    if cfg.format != "pdf":
        report.size = f"{max(1, len((report.content or '').encode('utf-8'))) / 1024:.1f} KB"

    await store.save_report(report_id, report.model_dump(mode="json"))
    return report.model_dump(mode="json")


@router.get("")
async def list_reports():
    return await store.list_reports()


@router.get("/{report_id}")
async def get_report(report_id: str):
    report = await store.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.get("/{report_id}/download")
async def download_report(report_id: str):
    report = await store.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    content = report.get("content") or ""
    fmt = report.get("format", "json")
    media_types = {
        "json": "application/json",
        "html": "text/html; charset=utf-8",
        "sarif": "application/sarif+json",
        "junit": "application/xml; charset=utf-8",
        "evidence": "application/json",
        "pdf": "application/pdf",
        "github_issues": "application/json",
        "jira": "application/json",
    }
    extensions = {"evidence": "json", "sarif": "sarif", "junit": "xml", "github_issues": "json", "jira": "json"}.get(fmt, fmt)
    headers = {"Content-Disposition": f'attachment; filename="{report_id}.{extensions}"'}
    if fmt == "pdf":
        return Response(
            content=base64.b64decode(content.encode("ascii")),
            media_type=media_types[fmt],
            headers=headers,
        )
    return Response(content=content, media_type=media_types.get(fmt, "text/plain"), headers=headers)


def _build_json_report(report_id: str, state, findings) -> str:
    return json.dumps(
        {
            "report_id": report_id,
            "scanner": "Centrix DAST",
            "scan_id": state.id,
            "target": state.config.target,
            "generated_at": datetime.utcnow().isoformat(),
            "findings": [finding.model_dump(mode="json") for finding in findings],
            "summary": _summary(findings),
        },
        indent=2,
    )


def _build_evidence_bundle(report_id: str, state, findings, evidence) -> str:
    return json.dumps(
        {
            "report_id": report_id,
            "scanner": "Centrix DAST",
            "scan_id": state.id,
            "target": state.config.target,
            "generated_at": datetime.utcnow().isoformat(),
            "summary": _summary(findings),
            "evidence": [item.model_dump(mode="json") for item in evidence],
            "findings": [finding.model_dump(mode="json") for finding in findings],
        },
        indent=2,
    )


def _build_html_report(report_id: str, state, findings) -> str:
    rows = ""
    for finding in findings:
        sev_color = {
            "Critical": "#e54646",
            "High": "#e07833",
            "Medium": "#c99a1a",
            "Low": "#3d82f6",
            "Info": "#64748b",
        }.get(finding.severity.value, "#888")
        rows += f"""
        <tr>
          <td style="color:{sev_color};font-weight:700">{finding.severity.value}</td>
          <td>{escape(finding.title)}</td>
          <td><code>{escape(finding.target)}</code></td>
          <td><code>{escape(finding.parameter)}</code></td>
          <td>{escape(finding.confidence)}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Centrix Report {report_id}</title>
<style>
  body{{font-family:Inter,Arial,sans-serif;background:#090c14;color:#dce4f0;padding:2rem}}
  h1{{color:#93c5fd}}table{{width:100%;border-collapse:collapse;margin-top:1rem}}
  th{{background:#131c2a;padding:.6rem 1rem;text-align:left;font-size:.75rem;text-transform:uppercase;letter-spacing:.1em}}
  td{{padding:.6rem 1rem;border-bottom:1px solid #1a2030;font-size:.8rem}}
  code{{background:#131c2a;padding:.1rem .4rem;border-radius:3px;font-size:.75rem}}
</style></head>
<body>
<h1>Centrix Security Report</h1>
<p>Scan: {escape(state.id)} | Target: {escape(state.config.target)} | Generated: {datetime.utcnow().isoformat()}</p>
<table>
<thead><tr><th>Severity</th><th>Title</th><th>Target</th><th>Parameter</th><th>Confidence</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</body></html>"""


def _build_sarif_report(report_id: str, state, findings) -> str:
    rules = {}
    results = []
    for finding in findings:
        rule_id = finding.cwe or finding.category.replace(" ", "-").lower()
        rules[rule_id] = {
            "id": rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "help": {"text": finding.recommendation},
        }
        results.append({
            "ruleId": rule_id,
            "level": _sarif_level(finding.severity.value),
            "message": {"text": finding.evidence or finding.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.target},
                },
            }],
            "properties": {
                "id": finding.id,
                "severity": finding.severity.value,
                "confidence": finding.confidence,
                "parameter": finding.parameter,
            },
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Centrix DAST",
                    "informationUri": state.config.target,
                    "rules": list(rules.values()),
                },
            },
            "automationDetails": {"id": report_id},
            "results": results,
        }],
    }, indent=2)


def _sarif_level(severity: str) -> str:
    return {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note", "Info": "none"}.get(severity, "warning")


def _build_junit_report(report_id: str, state, findings) -> str:
    cases = []
    for finding in findings:
        message = xml_escape(f"{finding.severity.value}: {finding.title}")
        detail = xml_escape(
            f"{finding.evidence}\nTarget: {finding.target}\n"
            f"Parameter: {finding.parameter}\nRecommendation: {finding.recommendation}"
        )
        cases.append(
            f'<testcase classname="centrix.{xml_escape(finding.category)}" name="{xml_escape(finding.id)}">'
            f'<failure message="{message}" type="{xml_escape(finding.severity.value)}">{detail}</failure>'
            "</testcase>"
        )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<testsuite name="Centrix DAST {xml_escape(report_id)}" tests="{len(findings)}" '
        f'failures="{len(findings)}" target="{xml_escape(state.config.target)}">'
        + "".join(cases)
        + "</testsuite>"
    )


def _summary(findings) -> dict:
    return {
        "total": len(findings),
        "critical": sum(1 for finding in findings if finding.severity.value == "Critical"),
        "high": sum(1 for finding in findings if finding.severity.value == "High"),
        "medium": sum(1 for finding in findings if finding.severity.value == "Medium"),
        "low": sum(1 for finding in findings if finding.severity.value == "Low"),
        "info": sum(1 for finding in findings if finding.severity.value == "Info"),
    }
