"""GitHub Issues export formatter for CENTRIX findings."""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional

from api.models import Finding, ScanState, EvidenceArtifact
from reporting.remediation import get_remediation_guide


def build_reproduction_curl(finding: Finding, artifact: Optional[EvidenceArtifact] = None) -> str:
    """Reconstruct an exact, executable cURL command from stored request metadata."""
    if finding.reproduction_curl:
        return finding.reproduction_curl

    method = (finding.request_method or (artifact.method if artifact else "GET")).upper()
    url = finding.target

    headers = dict(finding.request_headers) if finding.request_headers else {}
    if artifact and artifact.request_headers and not headers:
        headers = dict(artifact.request_headers)

    # If no headers stored, supply standard non-destructive audit headers
    if not headers:
        headers = {
            "User-Agent": "CENTRIX-Security-Auditor/4.0",
            "Accept": "*/*",
        }

    # Redact sensitive credentials in output command
    sanitized_headers = {}
    for k, v in headers.items():
        if k.lower() == "authorization":
            sanitized_headers[k] = "Bearer [REDACTED_AUTH_TOKEN]"
        elif k.lower() in ("cookie", "set-cookie") and "session" in str(v).lower():
            sanitized_headers[k] = "session=[REDACTED]"
        else:
            sanitized_headers[k] = str(v)

    body = finding.request_body
    if not body and artifact and artifact.request_body:
        body = artifact.request_body

    if not body and method in ("POST", "PUT", "PATCH") and finding.parameter:
        body = f"{finding.parameter}=CENTRIX_TEST_PAYLOAD"
        if "Content-Type" not in sanitized_headers and "content-type" not in sanitized_headers:
            sanitized_headers["Content-Type"] = "application/x-www-form-urlencoded"

    parts = ["curl -i -k"]
    if method != "GET":
        parts.append(f"-X {method}")

    for h_name, h_val in sanitized_headers.items():
        escaped_val = h_val.replace('"', '\\"')
        parts.append(f'-H "{h_name}: {escaped_val}"')

    if body:
        escaped_body = body.replace('"', '\\"').replace("\r", "").replace("\n", "\\n")
        parts.append(f'-d "{escaped_body}"')

    # If GET with query parameter not yet in URL
    if method == "GET" and finding.parameter and finding.parameter not in url:
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}{finding.parameter}=CENTRIX_TEST_PAYLOAD"

    parts.append(f'"{url}"')
    return " \\\n  ".join(parts)


def format_finding_as_github_issue(finding: Finding, state: ScanState) -> dict[str, Any]:
    """Convert a finding into a structured GitHub Issue creation payload."""
    severity = finding.severity.value
    cwe = finding.cwe or "CWE-Unknown"
    guide = get_remediation_guide(finding.category or finding.vuln_type)

    labels = [
        "security",
        "centrix-finding",
        f"severity:{severity.lower()}",
        f"cwe:{cwe.lower()}",
    ]
    if finding.classification:
        labels.append(f"classification:{finding.classification.value.lower()}")

    repro_curl = build_reproduction_curl(finding)

    code_fixes_md = ""
    for lang, snippet in guide.get("code_fixes", {}).items():
        lang_name = lang.replace("_", " ").title()
        code_fixes_md += f"\n<details>\n<summary><b>{lang_name}</b></summary>\n\n```\n{snippet}\n```\n</details>\n"

    server_configs_md = ""
    for srv, snippet in guide.get("server_configs", {}).items():
        srv_name = srv.capitalize()
        server_configs_md += f"\n<details>\n<summary><b>{srv_name} Configuration</b></summary>\n\n```\n{snippet}\n```\n</details>\n"

    body = f"""## 🛡️ Security Finding: {finding.title}

| Metric | Value |
| :--- | :--- |
| **Severity** | `{severity}` |
| **Classification** | `{finding.classification.value}` |
| **Confidence Score** | `{finding.confidence_score}/10` |
| **Target URL** | `{finding.target}` |
| **Affected Parameter** | `{finding.parameter or 'N/A'}` |
| **CWE ID** | `{cwe}` |
| **CVSS Score** | `{finding.cvss or 'N/A'}` |
| **Scan ID** | `{state.id}` |

---

### 📋 Description
{finding.description or guide.get('summary', '')}

### 🔍 Evidence & Observations
```
{finding.evidence or 'No direct raw payload excerpt stored.'}
```

### 🔁 Reproduction PoC
```bash
{repro_curl}
```

---

### 💡 Developer Remediation Guidance
{guide.get('summary', '')}

#### Recommended Code Patches
{code_fixes_md}

#### Edge & Server Defense
{server_configs_md}

#### Prevention Checklist
{chr(10).join(f"- [ ] {item}" for item in guide.get('prevention_checklist', []))}

---
*Reported automatically by [CENTRIX Autonomous Security Platform](https://github.com/harshraj211/Centrix) on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}.*
"""

    return {
        "title": f"[CENTRIX] [{severity}] {finding.title} on {finding.target}",
        "body": body,
        "labels": labels,
        "finding_id": finding.id,
    }


def build_github_issues_bundle(state: ScanState, findings: list[Finding]) -> str:
    """Produce a JSON bundle of GitHub Issues for automated ingestion or export."""
    issues = [format_finding_as_github_issue(f, state) for f in findings]
    return json.dumps({
        "generator": "CENTRIX GitHub Issues Exporter v4.0",
        "scan_id": state.id,
        "target": state.config.target,
        "generated_at": datetime.utcnow().isoformat(),
        "total_issues": len(issues),
        "issues": issues,
    }, indent=2)
