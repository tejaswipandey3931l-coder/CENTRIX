"""Tests for developer remediation and export formats (GitHub Issues, JIRA, SARIF)."""
import json
from api.models import (
    Finding,
    FindingClassification,
    ScanConfig,
    ScanState,
    Severity,
)
from reporting.github_issues import build_github_issues_bundle, format_finding_as_github_issue
from reporting.jira import build_jira_export_bundle, format_finding_as_jira_issue
from reporting.remediation import get_remediation_guide


def _mock_finding_and_state():
    config = ScanConfig(target="https://target.example.com", authorized=True)
    state = ScanState(id="SCN-TEST01", config=config)
    finding = Finding(
        id="VULN-001",
        scan_id=state.id,
        title="SQL Injection in user ID parameter",
        severity=Severity.critical,
        category="sql_injection",
        target="https://target.example.com/api/user",
        parameter="id",
        classification=FindingClassification.probable,
        confidence_score=8,
        cwe="CWE-89",
        cvss=9.8,
        evidence="SELECT * FROM users WHERE id = '1' OR '1'='1'",
        description="SQL injection vulnerability discovered in query param id",
    )
    return finding, state


def test_remediation_guide_lookup():
    guide = get_remediation_guide("sql_injection")
    assert "CWE-89" in guide["title"]
    assert "python_fastapi" in guide["code_fixes"]
    assert "nodejs_express" in guide["code_fixes"]
    assert "java_spring" in guide["code_fixes"]
    assert "go" in guide["code_fixes"]
    assert "nginx" in guide["server_configs"]
    assert len(guide["prevention_checklist"]) > 0


def test_format_finding_as_github_issue():
    finding, state = _mock_finding_and_state()
    issue = format_finding_as_github_issue(finding, state)
    assert "[CENTRIX] [Critical]" in issue["title"]
    assert "severity:critical" in issue["labels"]
    assert "cwe:cwe-89" in issue["labels"]
    assert "### 🔁 Reproduction PoC" in issue["body"]
    assert "curl" in issue["body"]
    assert "### 💡 Developer Remediation Guidance" in issue["body"]


def test_build_github_issues_bundle():
    finding, state = _mock_finding_and_state()
    bundle_str = build_github_issues_bundle(state, [finding])
    bundle = json.loads(bundle_str)
    assert bundle["total_issues"] == 1
    assert bundle["scan_id"] == "SCN-TEST01"
    assert len(bundle["issues"]) == 1


def test_jira_export_bundle():
    finding, state = _mock_finding_and_state()
    jira_str = build_jira_export_bundle(state, [finding], project_key="SEC")
    jira_data = json.loads(jira_str)
    assert "issueUpdates" in jira_data
    assert len(jira_data["issueUpdates"]) == 1
    fields = jira_data["issueUpdates"][0]["fields"]
    assert fields["project"]["key"] == "SEC"
    assert fields["priority"]["name"] == "Highest"
    assert "SQL Injection" in fields["summary"]
