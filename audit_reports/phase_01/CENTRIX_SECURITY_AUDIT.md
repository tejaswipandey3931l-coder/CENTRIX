# CENTRIX Security Audit: Vulnerabilities within the Scanner Itself

**Audit Mode**: Read-Only Forensic Architecture, Codebase & Runtime Audit  
**Phase**: Phase 01  
**Target**: CENTRIX Engine, API Server, and Background Workers  

---

## 1. Executive Summary

As a security testing tool designed to interact with hostile, untrusted external servers, CENTRIX must maintain rigorous defensive posture against malicious target servers, malicious network conditions, and unauthorized local/remote operators.

This forensic security audit evaluated CENTRIX against:
- Server-Side Request Forgery (SSRF) and Cloud Metadata Access
- Unauthenticated API Access and Cross-Origin Hijacking
- Injection Attacks (Command, Path Traversal, Stored XSS in Reports)
- Secret Storage and Credential Leakage
- Malicious Target Response Handling

---

## 2. Security Findings Matrix

| Vulnerability Vector | Description | Location | Severity | Forensic Classification |
|---|---|---|---|---|
| **SSRF via DNS Rebinding** | Pre-flight DNS validation can be bypassed using dual-A DNS records with low TTLs | `backend/scanner/safety.py:59-70` | **Critical** | **CONFIRMED** |
| **SSRF via Unvalidated Redirects** | Target servers returning HTTP 302 redirects to `http://169.254.169.254` or `http://127.0.0.1` are followed without safety validation | `backend/scanner/stages/probe.py` & `crawl.py` | **High** | **CONFIRMED** |
| **Complete Lack of API Authentication** | REST API and WebSockets do not authenticate callers; any local or network process can control the scanner | `backend/main.py`, `backend/api/routes/*` | **Critical** | **CONFIRMED** |
| **CORS Insecure Defaults with Credentials** | Unauthenticated API paired with permissive CORS origins allows malicious sites to pivot through the user's browser | `backend/main.py:23-35` | **High** | **CONFIRMED** |
| **Stored XSS in Scan Reports** | Untrusted payloads and target response snippets reflected into HTML/PDF reports without consistent entity escaping | `backend/reporting/pdf_report.py`, `scanner/report_generator.py` | **Medium** | **LIKELY** |
| **Plaintext Third-Party Secrets in DB** | Jira API tokens, GitHub Personal Access Tokens, and X-Kiro keys stored in plaintext SQLite JSON payloads | `backend/db/store.py:48`, `backend/integrations/*` | **High** | **CONFIRMED** |
| **Unrestricted Outbound Network Traffic** | No socket-level egress filtering to prevent scanner from reaching cloud link-local addresses | `backend/scanner/stages/probe.py` | **Medium** | **CONFIRMED** |
| **Unsafe Subprocess Execution** | Fixed argument execution in desktop script; no dynamic user input passed to shell | `desktop/centrix_desktop.py:21-41` | **Low** | **NOT APPLICABLE** |
| **Unsafe Object Deserialization** | System uses `json.loads` and Pydantic; no Python `pickle` deserialization detected | Entire codebase | **Informational** | **NOT APPLICABLE** |

---

## 3. Deep Dive into Confirmed Security Flaws

### 3.1 DNS Rebinding SSRF (CWE-918)
- **Vulnerability**: In `backend/scanner/safety.py:ensure_public_target`:
  ```python
  records = await asyncio.get_running_loop().getaddrinfo(host, None)
  addresses = {record[4][0] for record in records}
  if not addresses or any(not _is_public_ip(address) for address in addresses):
      raise TargetSafetyError("Targets resolving to private, local, or reserved addresses are not allowed")
  ```
- **Exploitation**: An attacker configures a domain name (e.g. `rebind.attacker.com`) with a DNS server that returns `1.1.1.1` on the first query (pre-flight check passes). When `probe.py` or `crawl.py` executes `session.get("http://rebind.attacker.com/...")`, `aiohttp` performs a new DNS lookup and receives `169.254.169.254` (AWS metadata) or `127.0.0.1`.
- **Impact**: The attacker forces the scanner to exfiltrate internal cloud credentials (IAM instance profile tokens) or interact with internal administrative services.

---

### 3.2 Unauthenticated API & Local Network Pivoting (CWE-306)
- **Vulnerability**: Every route in FastAPI is unauthenticated.
- **Exploitation Scenario**:
  1. A security analyst starts CENTRIX on their laptop (`localhost:8000`).
  2. While running the scan, the analyst browses the web and visits an attacker's website.
  3. The attacker's webpage executes JavaScript that sends background `fetch('http://localhost:8000/api/scans')` or WebSocket connections.
  4. Although CORS blocks direct reading of responses from unlisted origins, simple requests or WebSocket connections (which bypass SOP CORS restrictions) can be established to read live scan logs or trigger scans against internal corporate IPs.
- **Impact**: Total compromise of scanner operations, leakage of discovered vulnerabilities, and weaponization of the scanner as an unauthorized internal probe.

---

### 3.3 Plaintext Credential Storage in Database (CWE-312)
- **Vulnerability**: `backend/db/store.py` manages tables `auth_profiles`, `settings`, and `integration_outbox`.
- **Exploitation**: When users configure Jira tokens, GitHub access tokens, or basic authentication credentials for target websites, these strings are serialized directly into `centrix.db` as raw JSON strings without database encryption or key derivation.
- **Impact**: Any local process or backup exfiltration exposes high-privilege corporate credentials.

---

### 3.4 Stored XSS in Generated Reports (CWE-79)
- **Vulnerability**: `scanner/report_generator.py` and `backend/reporting/pdf_report.py` take vulnerability findings—including raw `payload` and `evidence` strings reflected from the untrusted target—and render them into HTML report tables.
- **Exploitation**: If a target application reflects a payload like `"><script>alert(document.cookie)</script>` or an malicious image tag with `onerror`, and the report generator fails to escape HTML entities before building the HTML/PDF report, opening the report in a browser executes the attacker's script in the context of the report reader.
- **Current State**: `html.escape` is used in some places in `report_generator.py`, but `backend/reporting/pdf_report.py` and `sarif_report.py` embed raw strings into JSON and ReportLab flowable paragraphs without full sanitization.

---

## 4. Hardening Recommendations

1. **Implement IP-Pinned Transport Layer**:
   - Create a custom `aiohttp.TCPConnector` that resolves hostnames once, checks the IP against `ipaddress.is_global`, and binds the socket strictly to that IP address for the entire HTTP session.
   - Disable automatic HTTP redirect following (`allow_redirects=False`) or inspect the `Location` header before following redirects to ensure the target IP is also global.
2. **Implement Local API Authentication**:
   - Generate a random, cryptographically secure session token on backend startup.
   - Require `X-Centrix-Token` or `Authorization: Bearer <token>` on all REST and WebSocket connections.
   - Pass this token to the frontend via an ephemeral bootstrap file or environment variable.
3. **Database Column-Level Secret Encryption**:
   - Use AES-GCM (via `cryptography.fernet` or `SecretBox`) with a locally derived machine key to encrypt all authentication credentials before inserting into `centrix.db`.
