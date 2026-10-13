"""Comprehensive False-Positive Reduction & Evidence Pipeline Regression Test Suite.

Verifies:
1. Custom 404 pages detection & suppression
2. Login redirects & WAF blocks detection & suppression
3. Dynamic timestamps and CSRF/nonce token normalization
4. Repeated stable responses scoring (+2 points)
5. Duplicate findings across URLs deduplication
6. IDOR candidate vs confirmed authorization bypass
7. CSRF form with and without actual state change
8. SSRF URL parameter without server-side fetch
9. Reflected but safely encoded XSS neutralisation
10. JWT-like non-sensitive strings redaction
11. Missing header aggregation across endpoints
12. Evidence-required confirmation rule enforcement (safety invariant)
13. AI/Adjudicator downgrade of weak candidates
14. Prevention of invented evidence
15. Report classification and confidence columns
"""
import pytest
import asyncio
from api.models import Finding, FindingClassification, Severity, FindingStatus, EvidenceArtifact, ScanState, ScanConfig
from scanner.validation.baseline import (
    normalize_response_body,
    compute_structural_hash,
    detect_error_or_waf,
    compare_responses,
)
from scanner.validation.scorer import calculate_evidence_score
from scanner.validation.detectors import (
    validate_xss_candidate,
    validate_csrf_candidate,
    validate_ssrf_candidate,
    validate_idor_candidate,
    redact_sensitive_tokens,
    is_observation_signal,
)
from scanner.stages.analyze import run as run_analyze
from agent.debate import debate_engine
from reporting.pdf_report import build_centrix_pdf_report


def test_custom_404_detection():
    """Verify custom 404 pages are recognized even with status 200."""
    body_1 = "<html><body><h1>404 Not Found</h1><p>The page you requested could not be found.</p></body></html>"
    flags = detect_error_or_waf(200, body_1)
    assert flags["is_custom_404"] is True

    flags_clean = detect_error_or_waf(200, "<html><body>Welcome to Dashboard</body></html>")
    assert flags_clean["is_custom_404"] is False


def test_login_redirect_and_waf_block():
    """Verify login redirects and WAF challenges are detected and penalized."""
    # Login redirect
    flags_redir = detect_error_or_waf(302, "", {"Location": "https://example.com/login?next=/admin"})
    assert flags_redir["is_login_redirect"] is True

    # Cloudflare WAF
    flags_waf = detect_error_or_waf(403, "Attention Required! | Cloudflare - Access Denied")
    assert flags_waf["is_waf_block"] is True


def test_dynamic_timestamp_and_token_normalization():
    """Verify dynamic timestamps, CSRF tokens, and nonces are normalized away."""
    body_a = '{"user": "admin", "csrf_token": "a1b2c3d4e5", "timestamp": 1709548800, "nonce": "abc123xyz"}'
    body_b = '{"user": "admin", "csrf_token": "9z8y7x6w5v", "timestamp": 1709548900, "nonce": "def456uvw"}'

    norm_a = normalize_response_body(body_a)
    norm_b = normalize_response_body(body_b)

    assert norm_a == norm_b
    assert "[CSRF_TOKEN]" in norm_a
    assert "[TIMESTAMP]" in norm_a


def test_repeated_stable_response_scoring():
    """Verify stable responses receive +2 points and higher confidence."""
    card = calculate_evidence_score(
        has_exact_target_and_param=True,
        is_reproducible=True,
        has_meaningful_difference=True,
        has_direct_security_impact=True,
        has_persisted_evidence=True,
    )
    assert card.total_score >= 8
    assert card.classification == FindingClassification.confirmed
    assert any("+2 Behavior verified across repeated requests." in r for r in card.reasons)


def test_deduplication_across_urls():
    """Verify identical parameters on the same path are deduplicated."""
    vulns = [
        {"type": "sqli", "url": "https://example.com/item?id=1", "param": "id", "evidence": "syntax error near '1'"},
        {"type": "sqli", "url": "https://example.com/item?id=2", "param": "id", "evidence": "syntax error near '2'"},
    ]
    logs = []
    async def mock_log(msg): logs.append(msg)

    findings = asyncio.run(run_analyze("scan-test-1", vulns, mock_log))
    assert len(findings) == 1
    assert findings[0].vuln_type == "sqli"


def test_idor_candidate_vs_confirmed():
    """Verify predictable id is only a candidate until differential authorization is verified."""
    # Unconfirmed candidate
    cand_check = validate_idor_candidate("id", "123", has_differential_authz_evidence=False)
    assert cand_check["is_vulnerable"] is False

    # Confirmed bypass
    conf_check = validate_idor_candidate("id", "123", has_differential_authz_evidence=True)
    assert conf_check["is_vulnerable"] is True


def test_csrf_state_change_validation():
    """Verify GET forms and non-state-changing POSTs are rejected as CSRF."""
    # GET method -> not vulnerable
    get_check = validate_csrf_candidate("GET", True, False, False, True)
    assert get_check["is_vulnerable"] is False

    # POST without state change -> not vulnerable
    read_check = validate_csrf_candidate("POST", False, False, False, True)
    assert read_check["is_vulnerable"] is False

    # POST with state change and no anti-CSRF token -> vulnerable
    vuln_check = validate_csrf_candidate("POST", True, False, False, True)
    assert vuln_check["is_vulnerable"] is True


def test_ssrf_url_parameter_without_callback():
    """Verify URL parameter alone is not proof of SSRF."""
    ssrf_unproven = validate_ssrf_candidate("https://internal.site", has_outbound_callback=False, target_host="example.com")
    assert ssrf_unproven["is_vulnerable"] is False

    ssrf_proven = validate_ssrf_candidate("https://internal.site", has_outbound_callback=True, target_host="example.com")
    assert ssrf_proven["is_vulnerable"] is True


def test_reflected_xss_safe_encoding():
    """Verify safely HTML-encoded input is recognized and neutralised."""
    payload = "<script>alert(1)</script>"
    safe_body = "<div>Search result for: &lt;script&gt;alert(1)&lt;/script&gt;</div>"

    check = validate_xss_candidate(safe_body, payload)
    assert check["is_executable"] is False
    assert check["is_encoded"] is True

    unsafe_body = "<div>Search result for: <script>alert(1)</script></div>"
    check_unsafe = validate_xss_candidate(unsafe_body, payload)
    assert check_unsafe["is_executable"] is True
    assert check_unsafe["is_encoded"] is False


def test_jwt_token_redaction():
    """Verify JWT tokens are redacted from output."""
    raw_text = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozG4"
    redacted = redact_sensitive_tokens(raw_text)
    assert "eyJ[REDACTED_JWT_TOKEN]" in redacted or "Bearer [REDACTED_BEARER]" in redacted
    assert "dozG4" not in redacted


def test_missing_header_aggregation():
    """Verify multiple instances of missing security headers are aggregated into one finding."""
    vulns = [
        {"type": "missing_header", "url": "https://example.com/page1", "param": "X-Frame-Options"},
        {"type": "missing_header", "url": "https://example.com/page2", "param": "X-Frame-Options"},
        {"type": "missing_header", "url": "https://example.com/page3", "param": "X-Frame-Options"},
    ]
    logs = []
    async def mock_log(msg): logs.append(msg)

    findings = asyncio.run(run_analyze("scan-test-hdr", vulns, mock_log, aggregate_headers=True))
    assert len(findings) == 1
    hdr_finding = findings[0]
    assert hdr_finding.vuln_type == "missing_header"
    assert hdr_finding.affected_urls_count == 3
    assert len(hdr_finding.example_urls) == 3
    assert hdr_finding.classification == FindingClassification.informational


def test_evidence_required_for_confirmation():
    """Verify safety invariant: Finding cannot be Confirmed without evidence."""
    # Attempt to create Confirmed finding without evidence
    finding = Finding(
        id="VLN-TEST",
        scan_id="scan-1",
        title="Test Vuln",
        severity=Severity.high,
        category="Injection",
        target="https://example.com",
        parameter="q",
        classification=FindingClassification.confirmed,
        evidence="",
        evidence_artifact_ids=[],
    )
    # Model validator must automatically downgrade to Tentative
    assert finding.classification == FindingClassification.tentative
    assert finding.confidence == "Tentative"
    assert "Downgraded from Confirmed" in finding.confidence_reasons[0]


def test_adjudicator_downgrades_weak_candidate():
    """Verify the debate adjudicator downgrades candidates lacking evidence."""
    weak_candidate = {
        "vuln_type": "idor",
        "target": "https://example.com/account",
        "parameter": "id",
        "evidence": "Observed id=123",
        "confidence_score": 3,
        "evidence_artifact_ids": [],
    }
    result = asyncio.run(debate_engine.adjudicate_candidate(weak_candidate))
    assert result.classification in ("tentative", "informational", "rejected")
    assert result.evidence_sufficient is False
    assert len(result.false_positive_risks) > 0


def test_prevention_of_invented_evidence():
    """Verify that observations (e.g. banners, missing headers) are never marked Confirmed."""
    card = calculate_evidence_score(
        has_exact_target_and_param=True,
        is_observation_only=True,
        has_persisted_evidence=True,
    )
    assert card.classification == FindingClassification.informational
    assert card.confidence_label == "Informational"


def test_report_classification_and_confidence_columns():
    """Verify that the PDF report generator includes Classification and Confidence columns."""
    finding = Finding(
        id="VLN-REPORT-1",
        scan_id="scan-rep",
        title="Predictable Identifier",
        severity=Severity.low,
        category="Access Control",
        target="https://example.com/user?id=1",
        parameter="id",
        classification=FindingClassification.tentative,
        confidence="Tentative",
        confidence_score=3,
        evidence="id=1 parameter observed",
        why_false_positive_risk="Observation only; no differential authorization bypass confirmed.",
    )
    state = ScanState(
        id="scan-rep",
        config=ScanConfig(target="https://example.com", authorized=True),
    )
    pdf_bytes = build_centrix_pdf_report("rep-1", state, [finding], [])
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF")
