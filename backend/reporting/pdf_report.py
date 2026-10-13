"""Centrix PDF report generator adapted from Wraith's ReportLab report flow."""
from __future__ import annotations

import datetime as dt
import html
from functools import partial
from io import BytesIO
from typing import Any
from urllib.parse import urlparse

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import PageBreak, Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False
    colors = None

from api.models import EvidenceArtifact, Finding, FindingClassification, ScanState, Severity

BRAND = "Centrix"
SCANNER_VERSION = "Centrix DAST Scanner"

SEVERITY_COLORS = {
    "Critical": colors.HexColor("#b91c1c") if colors else None,
    "High": colors.HexColor("#ea580c") if colors else None,
    "Medium": colors.HexColor("#ca8a04") if colors else None,
    "Low": colors.HexColor("#2563eb") if colors else None,
    "Info": colors.HexColor("#64748b") if colors else None,
}

OWASP_CATEGORIES = [
    ("A01", "Broken Access Control", ["Access Control", "Redirect", "Path Traversal"]),
    ("A02", "Cryptographic Failures", ["Cryptographic", "TLS"]),
    ("A03", "Injection", ["Injection", "XSS", "SQL Injection"]),
    ("A04", "Insecure Design", []),
    ("A05", "Security Misconfiguration", ["Security Headers", "Misconfiguration"]),
    ("A06", "Vulnerable and Outdated Components", ["Nuclei", "Components"]),
    ("A07", "Identification and Authentication Failures", ["Authentication"]),
    ("A08", "Software and Data Integrity Failures", []),
    ("A09", "Security Logging and Monitoring Failures", []),
    ("A10", "Server-Side Request Forgery", ["SSRF"]),
]


def build_centrix_pdf_report(
    report_id: str,
    state: ScanState,
    findings: list[Finding],
    evidence: list[EvidenceArtifact],
) -> bytes:
    """Return a polished multi-page Centrix PDF report as bytes."""
    if not HAS_REPORTLAB:
        raise RuntimeError("reportlab library is required to generate PDF reports. Install it with: pip install reportlab")
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.72 * inch,
        leftMargin=0.72 * inch,
        topMargin=0.72 * inch,
        bottomMargin=0.72 * inch,
        title=f"{BRAND} Security Assessment Report",
        author=SCANNER_VERSION,
    )
    styles = _styles()
    story: list[Any] = []

    _append_cover(story, styles, report_id, state, findings, evidence)
    _append_summary(story, styles, findings)
    _append_remediation_plan(story, styles, findings)
    _append_validation_required(story, styles, findings)
    _append_methodology(story, styles, state, evidence)
    _append_attack_scenarios(story, styles, findings)
    _append_toc(story, styles, findings)
    _append_details(story, styles, findings, evidence)
    _append_disclaimer(story, styles)


    footer = partial(_page_footer, target_url=state.config.target)
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "CentrixTitle",
            parent=base["Heading1"],
            fontSize=24,
            leading=28,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=4,
        ),
        "subtitle": ParagraphStyle(
            "CentrixSubtitle",
            parent=base["Normal"],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#2563eb"),
        ),
        "muted": ParagraphStyle("CentrixMuted", parent=base["Normal"], fontSize=8, leading=10, textColor=colors.HexColor("#64748b")),
        "h1": ParagraphStyle("CentrixH1", parent=base["Heading1"], fontSize=15, leading=18, textColor=colors.HexColor("#0f172a")),
        "h2": ParagraphStyle("CentrixH2", parent=base["Heading2"], fontSize=12, leading=15, textColor=colors.HexColor("#1e293b")),
        "normal": ParagraphStyle("CentrixNormal", parent=base["Normal"], fontSize=9, leading=12),
        "small": ParagraphStyle("CentrixSmall", parent=base["Normal"], fontSize=7.5, leading=10, textColor=colors.HexColor("#475569")),
        "code": ParagraphStyle(
            "CentrixCode",
            parent=base["Normal"],
            fontName="Courier",
            fontSize=7.5,
            leading=9.5,
            textColor=colors.HexColor("#111827"),
            backColor=colors.HexColor("#f8fafc"),
            borderPadding=5,
        ),
    }


def _append_cover(story: list[Any], styles: dict[str, ParagraphStyle], report_id: str, state: ScanState, findings: list[Finding], evidence: list[EvidenceArtifact]) -> None:
    story.append(Paragraph("CENTRIX", styles["title"]))
    story.append(Paragraph("DYNAMIC APPLICATION SECURITY TESTING", styles["subtitle"]))
    story.append(Spacer(1, 8))
    story.append(_label_bar("CONFIDENTIAL SECURITY REPORT", colors.HexColor("#1e293b")))
    story.append(Spacer(1, 18))
    story.append(Paragraph("Security Assessment Report", styles["h1"]))
    story.append(Spacer(1, 12))

    generated_at = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
    duration = f"{state.duration_s:.0f}s" if state.duration_s else "N/A"
    cover_rows = [
        ["Report ID", report_id],
        ["Scan ID", state.id],
        ["Target", state.config.target],
        ["Environment", state.config.environment],
        ["Scan Profile", state.config.profile.value],
        ["Generated", generated_at],
        ["Duration", duration],
    ]
    story.append(_key_value_table(cover_rows))
    story.append(Spacer(1, 18))

    counts = _severity_counts(findings)
    story.append(_risk_tile_row(counts, len(evidence)))
    story.append(Spacer(1, 14))
    score_rows = [
        ["Metric", "Value"],
        ["Overall Risk", _overall_risk(counts)],
        ["Findings", str(len(findings))],
        ["Captured Evidence", str(len(evidence))],
        ["Critical / High", f"{counts['Critical']} / {counts['High']}"],
    ]
    table = Table(score_rows, colWidths=[2.4 * inch, 2.6 * inch])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(table)
    story.append(Spacer(1, 18))
    story.append(Paragraph(
        "This report was generated from authorised DAST scan data. Results should be validated and "
        "prioritized alongside business context before remediation deadlines are set.",
        styles["normal"],
    ))
    story.append(PageBreak())


def _append_summary(story: list[Any], styles: dict[str, ParagraphStyle], findings: list[Finding]) -> None:
    story.append(Paragraph("Executive Summary", styles["h1"]))
    story.append(Spacer(1, 8))
    counts = _severity_counts(findings)
    risk = _overall_risk(counts)
    if counts["Critical"] or counts["High"]:
        summary = (
            f"The assessment identified {counts['Critical']} critical and {counts['High']} high severity findings. "
            "These issues should be reviewed immediately because they may enable data access, account abuse, "
            "or service compromise."
        )
    elif findings:
        summary = (
            f"The assessment identified {len(findings)} findings, with an overall risk rating of {risk}. "
            "Most issues can be reduced by hardening exposed controls and validating affected endpoints manually."
        )
    else:
        summary = "No findings were recorded for this scan. Continue periodic testing and monitoring."
    story.append(Paragraph(summary, styles["normal"]))
    story.append(Spacer(1, 12))

    risk_rows = [["Severity", "Count"]]
    for severity in ["Critical", "High", "Medium", "Low", "Info"]:
        risk_rows.append([severity, str(counts[severity])])
    table = Table(risk_rows, colWidths=[2.0 * inch, 1.0 * inch])
    table.setStyle(_table_style(header=colors.HexColor("#1e293b")))
    for row_index, severity in enumerate(["Critical", "High", "Medium", "Low", "Info"], start=1):
        table.setStyle(TableStyle([("TEXTCOLOR", (0, row_index), (0, row_index), SEVERITY_COLORS[severity])]))
    story.append(Paragraph("Risk Breakdown", styles["h2"]))
    story.append(table)
    story.append(Spacer(1, 12))

    story.append(Paragraph("OWASP Top 10 Coverage", styles["h2"]))
    owasp_rows = [["Category", "Status", "Findings"]]
    for code, name, categories in OWASP_CATEGORIES:
        matched = [f for f in findings if any(category.lower() in f.category.lower() or category.lower() in f.title.lower() for category in categories)]
        status = "Found" if matched else ("Tested - Clean" if categories else "Not Tested")
        owasp_rows.append([f"{code}: {name}", status, str(len(matched))])
    owasp_table = Table(owasp_rows, colWidths=[3.25 * inch, 1.25 * inch, 0.7 * inch])
    owasp_table.setStyle(_table_style(header=colors.HexColor("#0f172a"), font_size=7.7))
    story.append(owasp_table)
    story.append(Spacer(1, 14))

    if findings:
        story.append(Paragraph("Findings Summary & Evidence Classification", styles["h2"]))
        summary_rows = [["ID", "Severity", "Class", "Conf", "Finding", "Target", "Param", "Evid", "Status"]]
        for finding in _sorted_findings(findings):
            path = urlparse(finding.target).path or "/"
            cls_val = getattr(finding, "classification", None)
            cls_str = cls_val.value if hasattr(cls_val, "value") else str(cls_val or finding.confidence)
            conf_score = getattr(finding, "confidence_score", 4)
            evid_count = len(getattr(finding, "evidence_artifact_ids", []) or ([1] if finding.evidence else []))
            is_info = (
                cls_val == FindingClassification.informational
                or cls_str == "Informational"
                or finding.confidence == "Informational"
                or finding.severity == Severity.info
                or conf_score <= 2
                or "observation" in finding.title.lower()
            )
            displayed_sev = "Info" if is_info else finding.severity.value
            summary_rows.append([
                Paragraph(finding.id[:8], styles["small"]),
                Paragraph(displayed_sev, styles["small"]),
                Paragraph(cls_str, styles["small"]),
                Paragraph(f"{conf_score}/10", styles["small"]),
                Paragraph(_clip(finding.title, 30), styles["small"]),
                Paragraph(_clip(path, 18), styles["small"]),
                Paragraph(_clip(finding.parameter or "-", 10), styles["small"]),
                Paragraph(str(evid_count), styles["small"]),
                Paragraph(getattr(finding, "validation_status", "pending"), styles["small"]),
            ])
        summary_table = Table(
            summary_rows,
            colWidths=[0.75 * inch, 0.6 * inch, 0.7 * inch, 0.45 * inch, 1.7 * inch, 1.1 * inch, 0.65 * inch, 0.4 * inch, 0.7 * inch],
        )
        summary_table.setStyle(_table_style(header=colors.HexColor("#334155"), font_size=6.8))
        story.append(summary_table)
    story.append(PageBreak())



def _append_remediation_plan(story: list[Any], styles: dict[str, ParagraphStyle], findings: list[Finding]) -> None:
    story.append(Paragraph("Remediation Plan", styles["h1"]))
    story.append(Spacer(1, 8))
    if not findings:
        story.append(Paragraph("No remediation tasks are required from this scan.", styles["normal"]))
        story.append(PageBreak())
        return

    story.append(Paragraph(
        "Use this plan to triage findings by severity and confidence. The suggested timelines are starting "
        "points; shorten them for internet-facing, unauthenticated, or business-critical assets.",
        styles["normal"],
    ))
    story.append(Spacer(1, 10))

    sla_rows = [
        ["Severity", "Suggested owner action", "Target SLA"],
        ["Critical", "Stop exposure, patch or mitigate immediately, then retest.", "24-48 hours"],
        ["High", "Assign to owning team, create fix branch, verify exploit path.", "7 days"],
        ["Medium", "Patch in normal sprint, add regression coverage.", "30 days"],
        ["Low / Info", "Review as hardening backlog and document acceptance if needed.", "60-90 days"],
    ]
    table = Table(sla_rows, colWidths=[0.9 * inch, 3.5 * inch, 1.0 * inch])
    table.setStyle(_table_style(header=colors.HexColor("#0f172a"), font_size=7.7))
    story.append(table)
    story.append(Spacer(1, 14))

    priority_rows = [["Priority", "Finding", "Severity", "Owner Hint", "Retest"]]
    actionable_findings = [
        f for f in _sorted_findings(findings)
        if f.severity.value in {"Critical", "High", "Medium"}
        and getattr(f, "classification", None) not in (FindingClassification.informational, "Informational")
        and getattr(f, "confidence", "") != "Informational"
        and getattr(f, "confidence_score", 4) >= 3
        and "observation" not in f.title.lower()
    ]
    if actionable_findings:
        for index, finding in enumerate(actionable_findings[:12], start=1):
            owner = _owner_hint(finding)
            priority_rows.append([
                f"P{index}",
                Paragraph(_esc(_clip(finding.title, 54)), styles["small"]),
                finding.severity.value,
                owner,
                "Required",
            ])
    else:
        priority_rows.append([
            "-",
            Paragraph("No critical or high-priority vulnerabilities identified; remaining items are informational hardening observations.", styles["small"]),
            "Info",
            "SecOps/Dev",
            "Optional",
        ])
    priority_table = Table(priority_rows, colWidths=[0.45 * inch, 2.25 * inch, 0.75 * inch, 1.25 * inch, 0.75 * inch])
    priority_table.setStyle(_table_style(header=colors.HexColor("#334155"), font_size=7.0))
    story.append(Paragraph("Prioritized Fix Queue", styles["h2"]))
    story.append(priority_table)
    story.append(PageBreak())


def _append_validation_required(story: list[Any], styles: dict[str, ParagraphStyle], findings: list[Finding]) -> None:
    pending_findings = [
        f for f in findings
        if getattr(f, "classification", None) in ("Tentative", "Probable")
        or getattr(getattr(f, "classification", None), "value", "") in ("Tentative", "Probable")
        or getattr(f, "validation_status", "") == "pending"
    ]
    if not pending_findings:
        return

    story.append(Paragraph("Manual Validation Required", styles["h1"]))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "The following items represent candidates, unconfirmed observations, or weak signals where "
        "direct proof of exploitability was unavailable during automated testing. These findings must "
        "be reviewed and verified manually before setting remediation SLAs.",
        styles["normal"],
    ))
    story.append(Spacer(1, 10))

    val_rows = [["ID", "Finding", "Classification", "Confidence", "Why Validation is Required"]]
    for f in pending_findings:
        cls_val = getattr(f, "classification", None)
        cls_str = cls_val.value if hasattr(cls_val, "value") else str(cls_val or f.confidence)
        conf_score = getattr(f, "confidence_score", 4)
        risk_why = getattr(f, "why_false_positive_risk", None) or "Lacks direct reproduction artifact."
        val_rows.append([
            Paragraph(f.id[:8], styles["small"]),
            Paragraph(_clip(f.title, 32), styles["small"]),
            Paragraph(cls_str, styles["small"]),
            Paragraph(f"{conf_score}/10", styles["small"]),
            Paragraph(_clip(risk_why, 60), styles["small"]),
        ])

    table = Table(val_rows, colWidths=[0.8 * inch, 1.8 * inch, 0.9 * inch, 0.6 * inch, 2.74 * inch])
    table.setStyle(_table_style(header=colors.HexColor("#ca8a04"), font_size=7.2))
    story.append(table)
    story.append(PageBreak())



def _append_methodology(story: list[Any], styles: dict[str, ParagraphStyle], state: ScanState, evidence: list[EvidenceArtifact]) -> None:
    story.append(Paragraph("Methodology and Scope", styles["h1"]))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "Centrix performed dynamic application testing against the authorised target using discovery, "
        "crawl, passive analysis, active probes, evidence capture, and report aggregation.",
        styles["normal"],
    ))
    story.append(Spacer(1, 8))
    rows = [
        ["Target", state.config.target],
        ["Scope Patterns", "\n".join(state.config.scope) if state.config.scope else "Same-origin target scope"],
        ["Safety Mode", state.config.safety.value],
        ["Max Requests", str(state.config.max_requests)],
        ["Robots Policy", "Respected" if state.config.respect_robots else "Not enforced"],
        ["Evidence Records", str(len(evidence))],
    ]
    story.append(_key_value_table(rows))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Compliance Reference", styles["h2"]))
    compliance_rows = [
        ["Standard", "Relevant Controls"],
        ["PCI DSS 4.0", "6.2 secure development, 6.4 public-facing application protection"],
        ["SOC 2", "CC6.1 logical access, CC7.1 system monitoring"],
        ["ISO 27001:2022", "A.8.26 application security, A.8.28 secure coding"],
        ["NIST 800-53", "SA-11 developer testing, SI-10 input validation"],
        ["GDPR", "Article 32 security of processing"],
    ]
    table = Table(compliance_rows, colWidths=[1.5 * inch, 3.9 * inch])
    table.setStyle(_table_style(header=colors.HexColor("#0f172a"), font_size=7.7))
    story.append(table)
    story.append(PageBreak())


def _append_attack_scenarios(story: list[Any], styles: dict[str, ParagraphStyle], findings: list[Finding]) -> None:
    if not findings:
        return
    story.append(Paragraph("Potential Attack Scenarios", styles["h1"]))
    story.append(Spacer(1, 8))
    for index, finding in enumerate(findings[:5], start=1):
        story.append(Paragraph(f"Scenario {index}: {_esc(finding.title)}", styles["h2"]))
        story.append(Paragraph(
            f"An attacker identifies the affected target ({_esc(finding.target)}) and attempts to exploit "
            f"the weakness around {_esc(finding.parameter or 'the affected control')}. Successful exploitation "
            "could affect confidentiality, integrity, or availability depending on business logic.",
            styles["normal"],
        ))
        story.append(Spacer(1, 6))
        steps = [
            "Locate the affected URL and parameter from the finding evidence.",
            "Reproduce the observed behavior using a controlled test request.",
            "Assess whether authentication, authorization, or input validation changes the result.",
            "Apply remediation and retest the same path in Centrix.",
        ]
        for step in steps:
            story.append(Paragraph(f"- {_esc(step)}", styles["normal"]))
        story.append(Spacer(1, 10))
    story.append(PageBreak())


def _append_toc(story: list[Any], styles: dict[str, ParagraphStyle], findings: list[Finding]) -> None:
    story.append(Paragraph("Table of Contents", styles["h1"]))
    story.append(Spacer(1, 8))
    story.append(Paragraph("1. Executive Summary", styles["normal"]))
    story.append(Paragraph("2. Remediation Plan", styles["normal"]))
    story.append(Paragraph("3. Methodology and Scope", styles["normal"]))
    story.append(Paragraph("4. Potential Attack Scenarios", styles["normal"]))
    story.append(Paragraph("5. Detailed Findings", styles["normal"]))
    if findings:
        story.append(Spacer(1, 8))
        for index, finding in enumerate(findings, start=1):
            story.append(Paragraph(f"5.{index} {_esc(finding.title)}", styles["small"]))
    story.append(PageBreak())


def _append_details(story: list[Any], styles: dict[str, ParagraphStyle], findings: list[Finding], evidence: list[EvidenceArtifact]) -> None:
    story.append(Paragraph("Detailed Findings", styles["h1"]))
    if not findings:
        story.append(Paragraph("No findings were recorded for this scan.", styles["normal"]))
        story.append(PageBreak())
        return

    evidence_by_url = {item.url: item for item in evidence}
    for index, finding in enumerate(_sorted_findings(findings), start=1):
        story.append(Paragraph(f"{index}. {_esc(finding.title)}", styles["h1"]))
        story.append(Spacer(1, 6))
        badge = Table([[finding.severity.value.upper()]], colWidths=[1.55 * inch])
        badge.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), SEVERITY_COLORS.get(finding.severity.value, colors.grey)),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(badge)
        story.append(Spacer(1, 8))

        cls_val = getattr(finding, "classification", None)
        cls_str = cls_val.value if hasattr(cls_val, "value") else str(cls_val or finding.confidence)
        conf_score = getattr(finding, "confidence_score", 4)
        repro_status = getattr(finding, "reproduction_status", "untested")
        val_status = getattr(finding, "validation_status", "pending")
        evid_ids = getattr(finding, "evidence_artifact_ids", []) or ([finding.id] if finding.evidence else [])

        glance_rows = [
            ["Severity", finding.severity.value],
            ["Classification", cls_str],
            ["Confidence", f"{conf_score}/10 ({finding.confidence})"],
            ["CVSS", str(finding.cvss or "N/A")],
            ["CWE", finding.cwe or "N/A"],
            ["Category", finding.category],
            ["Target", finding.target],
            ["Parameter", finding.parameter or "N/A"],
            ["Reproduction", repro_status],
            ["Validation Status", val_status],
            ["Evidence Artifacts", str(len(evid_ids))],
            ["Status", finding.status.value],
            ["Suggested Owner", _owner_hint(finding)],
            ["Retest Priority", "Required" if finding.severity.value in {"Critical", "High", "Medium"} else "Optional"],
        ]
        story.append(_key_value_table(glance_rows))
        story.append(Spacer(1, 10))

        why_risk = getattr(finding, "why_false_positive_risk", None)
        if why_risk:
            story.append(Paragraph("Why this may be a false positive", styles["h2"]))
            warn_table = Table([[Paragraph(f"<b>False-Positive Risk Analysis:</b> {_esc(why_risk)}", styles["small"])]], colWidths=[6.84 * inch])
            warn_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fef3c7")),
                ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#f59e0b")),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ]))
            story.append(warn_table)
            story.append(Spacer(1, 8))

        story.append(Paragraph("Description", styles["h2"]))
        story.append(Paragraph(_esc(finding.description), styles["normal"]))
        story.append(Spacer(1, 8))


        story.append(Paragraph("Evidence", styles["h2"]))
        evidence_block = _evidence_block(finding, evidence_by_url.get(finding.target))
        story.append(Preformatted(evidence_block, styles["code"]))
        story.append(Spacer(1, 8))

        story.append(Paragraph("Remediation", styles["h2"]))
        for line in _remediation_lines(finding):
            story.append(Paragraph(f"- {_esc(line)}", styles["normal"]))
        story.append(Spacer(1, 8))

        story.append(Paragraph("Retest Checklist", styles["h2"]))
        for line in _retest_lines(finding):
            story.append(Paragraph(f"- {_esc(line)}", styles["normal"]))
        story.append(Spacer(1, 8))

        story.append(Paragraph("References", styles["h2"]))
        story.append(Paragraph("https://owasp.org/", styles["small"]))
        if finding.cwe:
            story.append(Paragraph("https://cwe.mitre.org/", styles["small"]))
        story.append(PageBreak())


def _append_disclaimer(story: list[Any], styles: dict[str, ParagraphStyle]) -> None:
    story.append(Paragraph("Disclaimer", styles["h1"]))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "This report is provided for security assessment and remediation planning. Automated DAST results "
        "can include false positives and false negatives. Validate high-impact findings manually before "
        "external disclosure or production changes.",
        styles["normal"],
    ))


def _page_footer(canvas, _doc, target_url: str) -> None:
    canvas.saveState()
    width, height = letter
    canvas.setStrokeColor(colors.HexColor("#cbd5e1"))
    canvas.line(0.72 * inch, 0.62 * inch, width - 0.72 * inch, 0.62 * inch)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#475569"))
    canvas.drawString(0.72 * inch, 0.42 * inch, f"Generated by {SCANNER_VERSION}")
    canvas.drawRightString(width - 0.72 * inch, 0.42 * inch, f"Page {canvas.getPageNumber()}")
    if canvas.getPageNumber() > 1:
        canvas.drawString(0.72 * inch, height - 0.45 * inch, f"{BRAND} Security Report: {_clip(target_url, 80)}")
    canvas.restoreState()


def _key_value_table(rows: list[list[str]]) -> Table:
    body = [[Paragraph(f"<b>{_esc(key)}</b>", _styles()["normal"]), Paragraph(_esc(value), _styles()["normal"])] for key, value in rows]
    table = Table(body, colWidths=[1.65 * inch, 3.95 * inch])
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eff6ff")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return table


def _label_bar(label: str, color: Any) -> Table:
    table = Table([[label]], colWidths=[5.6 * inch])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def _risk_tile_row(counts: dict[str, int], evidence_count: int) -> Table:
    rows = [[
        Paragraph(f"<b>{counts['Critical']}</b><br/>Critical", _styles()["normal"]),
        Paragraph(f"<b>{counts['High']}</b><br/>High", _styles()["normal"]),
        Paragraph(f"<b>{counts['Medium']}</b><br/>Medium", _styles()["normal"]),
        Paragraph(f"<b>{counts['Low']}</b><br/>Low", _styles()["normal"]),
        Paragraph(f"<b>{evidence_count}</b><br/>Evidence", _styles()["normal"]),
    ]]
    table = Table(rows, colWidths=[1.02 * inch] * 5)
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.white),
        ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#fee2e2")),
        ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#ffedd5")),
        ("BACKGROUND", (2, 0), (2, 0), colors.HexColor("#fef3c7")),
        ("BACKGROUND", (3, 0), (3, 0), colors.HexColor("#dbeafe")),
        ("BACKGROUND", (4, 0), (4, 0), colors.HexColor("#e2e8f0")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return table


def _table_style(header: Any = None, font_size: float = 8.0) -> Any:
    header = header or (colors.HexColor("#0f172a") if colors else None)
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), header),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white if colors else None),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1") if colors else None),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")] if colors else []),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), font_size),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ])


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for finding in findings:
        cls_val = getattr(finding, "classification", None)
        is_info = (
            cls_val == FindingClassification.informational
            or getattr(cls_val, "value", "") == "Informational"
            or finding.confidence == "Informational"
            or finding.severity == Severity.info
            or getattr(finding, "confidence_score", 4) <= 2
            or "observation" in finding.title.lower()
        )
        if is_info:
            counts["Info"] += 1
        else:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
    return counts


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    def rank_key(finding: Finding):
        cls_val = getattr(finding, "classification", None)
        is_info = (
            cls_val == FindingClassification.informational
            or getattr(cls_val, "value", "") == "Informational"
            or finding.confidence == "Informational"
            or finding.severity == Severity.info
            or getattr(finding, "confidence_score", 4) <= 2
            or "observation" in finding.title.lower()
        )
        sev_rank = 4 if is_info else _severity_rank(finding.severity.value)
        return (sev_rank, finding.title.lower())
    return sorted(findings, key=rank_key)


def _severity_rank(value: str) -> int:
    return {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}.get(value, 5)


def _overall_risk(counts: dict[str, int]) -> str:
    if counts.get("Critical"):
        return "Critical"
    if counts.get("High"):
        return "High"
    if counts.get("Medium"):
        return "Medium"
    if counts.get("Low"):
        return "Low"
    return "Informational"


def _evidence_block(finding: Finding, evidence: EvidenceArtifact | None) -> str:
    if evidence:
        headers = "\n".join(f"{key}: {value}" for key, value in list(evidence.response_headers.items())[:10])
        return _wrap_text(
            f"{evidence.method} {evidence.url} HTTP/1.1\n"
            f"HTTP {evidence.status_code}\n"
            f"Content-Type: {evidence.content_type or 'unknown'}\n"
            f"Response-Length: {evidence.response_length}\n"
            f"{headers}\n\n"
            f"{_plain(finding.evidence or evidence.response_excerpt)[:1500]}"
        )
    return _wrap_text(
        f"Target: {finding.target}\n"
        f"Parameter: {finding.parameter or 'N/A'}\n"
        f"Evidence: {_plain(finding.evidence)[:1500]}"
    )


def _remediation_lines(finding: Finding) -> list[str]:
    raw = _plain(finding.recommendation)
    if not raw:
        return ["Review the affected control, apply framework guidance, and retest the finding."]
    parts = [part.strip(" .") for part in raw.replace("\n", " ").split(".") if part.strip()]
    return parts[:5] or [raw]


def _retest_lines(finding: Finding) -> list[str]:
    path = urlparse(finding.target).path or "/"
    return [
        f"Re-run the original request against {path} after the fix is deployed.",
        "Confirm the vulnerable payload no longer changes response behavior or data access.",
        "Capture before/after evidence in Proof Mode and attach it to the finding.",
        "Keep the regression test in the owning service or API test suite.",
    ]


def _owner_hint(finding: Finding) -> str:
    text = f"{finding.category} {finding.title}".lower()
    if any(marker in text for marker in ("graphql", "api", "idor", "access control", "jwt", "csrf")):
        return "Backend/API"
    if any(marker in text for marker in ("xss", "dom", "content security", "header")):
        return "Frontend/Web"
    if any(marker in text for marker in ("tls", "crypto", "component", "nuclei", "misconfiguration")):
        return "Platform/SecOps"
    if any(marker in text for marker in ("sql", "injection", "ssti", "xxe", "ssrf")):
        return "Backend/Security"
    return "App owner"


def _wrap_text(value: str, width: int = 92) -> str:
    lines: list[str] = []
    for raw_line in str(value or "").splitlines():
        line = raw_line
        while len(line) > width:
            lines.append(line[:width])
            line = line[width:]
        lines.append(line)
    return "\n".join(lines)


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else "N/A"))


def _plain(value: Any) -> str:
    return " ".join(str(value or "N/A").split())


def _clip(value: Any, length: int) -> str:
    text = str(value or "N/A")
    return text if len(text) <= length else text[: max(0, length - 3)] + "..."
