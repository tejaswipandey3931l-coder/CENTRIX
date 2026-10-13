# CENTRIX Detection Accuracy & Vulnerability Detector Forensic Audit

**Audit Mode**: Read-Only Forensic Architecture, Codebase & Runtime Audit  
**Phase**: Phase 01  
**Scope**: Every active and passive vulnerability detector implemented in CENTRIX  

> [!NOTE]  
> Per forensic audit guidelines, no speculative or fabricated accuracy percentages are stated in this document. All evaluations are derived directly from source code inspection, AST verification, and local execution behavior.

---

## 1. Detector-by-Detector Forensic Evaluation

### 1.1 Reflected Cross-Site Scripting (XSS)
- **Files**: `backend/scanner/stages/probe.py` (`_test_xss`, lines 280-307; `_form_probes`, lines 927-937); `backend/scanner/validation/detectors.py` (`validate_xss_candidate`).
- **Input Tested**: Query parameters extracted from crawled URLs and text input fields in HTML forms.
- **Payloads Sent**: `<script>alert(1)</script>`, `"><img src=x onerror=alert(1)>`.
- **Response Inspected**: Raw HTTP response body (string search).
- **Positive Condition**: `if payload in body: results.append(...)`.
- **Evidence Stored**: Snippet string: `"Payload '<script>alert(1)</script>' reflected in response"`.
- **Exploitability Verification**: 
  - **In `probe.py`**: **None**. It equates *raw substring reflection* directly with *confirmed execution*.
  - **In `validation/detectors.py`**: Partial helper `validate_xss_candidate` tests for HTML entities (`&lt;script&gt;`), but is only invoked in re-test/analyze flows, not in the initial probe loop.
  - Does NOT check response `Content-Type` (e.g. `application/json`, `text/plain`).
  - Does NOT check DOM context (e.g. whether reflection occurs inside a `<script>` string, `<textarea>`, HTML comment, or disabled attribute).
  - Does NOT execute JavaScript via browser to confirm DOM execution.
- **Severity & CWE**: Hardcoded High / Critical, CWE-79, CVSS 7.5.
- **Deduplication**: Deduplicated on `(url, param, "xss")`.
- **False-Positive Conditions**:
  1. Reflection in JSON API responses: An API returning `{"query": "<script>alert(1)</script>"}` with `Content-Type: application/json` is erroneously flagged as Confirmed XSS.
  2. Reflection inside `<textarea>` or `<pre>` tags where scripts do not execute.
  3. Non-executable reflection in HTML attributes without quote breakouts.
- **False-Negative Conditions**:
  1. Double question-mark URL bug: When testing URLs with existing parameters (`http://target/search?lang=en`), `probe.py` appends `?param=payload`, resulting in invalid query strings ignored by the server.
  2. Unencoded payload transmission: `<script>` tags sent without URL encoding (`%3Cscript%3E`) are rejected by modern web servers/WAFs before reaching the application.
  3. DOM-based XSS: Missed completely because the static request probe cannot execute client-side JavaScript.
  4. Context-breaking payloads (e.g. template literals `${alert(1)}`, script block breakout `</script>`, event handlers `onfocus=alert(1)`) are omitted from the default payload list.

---

### 1.2 SQL Injection (SQLi)
- **Files**: `backend/scanner/stages/probe.py` (`_test_sqli_v2`, lines 208-258; `_form_probes`, lines 938-950).
- **Input Tested**: Query parameters and form inputs.
- **Payloads Sent**:
  - Error-based: `'`, `' OR '1'='1`, `1 AND 1=1`, `1 AND 1=2`.
  - Boolean pairs: `("1 OR 1=1", "1 AND 1=2")`, `("' OR '1'='1", "' AND '1'='2")`, `("1') OR ('1'='1", "1') AND ('1'='2")`.
- **Response Inspected**: 
  - Substring check against `SQLI_ERRORS` (list of standard RDBMS error strings: `syntax error`, `ora-`, `sqlite3.`, `mysql_fetch`, etc.).
  - Response fingerprint: `(status, normalized_length, title)`.
- **Positive Condition**:
  - Error detected in response body, OR
  - True payload matches baseline fingerprint while False payload differs by >= 125 chars or 15%.
- **Evidence Stored**: `"SQL error string detected: '{err}'"` or `"True response matched baseline; false response differed ({true_fp} vs {false_fp})"`.
- **Exploitability Verification**:
  - Error-based: Does not distinguish between a generic database error and an exploitable injection channel.
  - Boolean differential: Brittle length modulus `(len(body) // 25) * 25`.
  - Time-based detection: Completely omitted from default active probing.
- **Severity & CWE**: Critical / High, CWE-89, CVSS 9.8.
- **False-Positive Conditions**:
  1. Dynamic content shift: Any page where content length naturally varies across successive requests (e.g., dynamic timestamps, rotating banner text, dynamic anti-CSRF tokens) triggers a false positive boolean SQLi match.
  2. Diagnostic or debug error pages: Applications displaying generic SQL errors on invalid input without exploitable parameter concatenation.
- **False-Negative Conditions**:
  1. Blind time-based SQL injection: Cannot detect blind injections where response length and error messages remain constant.
  2. Second-order SQL injection: Cannot detect delayed injections triggered on subsequent pages.
  3. JSON body parameters: `_test_sqli_v2` only tests GET query parameters, missing REST API endpoints expecting JSON payloads.

---

### 1.3 Path Traversal / Local File Inclusion (LFI)
- **Files**: `backend/scanner/stages/probe.py` (`_test_traversal`, lines 309-339).
- **Input Tested**: Query parameters.
- **Payloads Sent**: `../../etc/passwd`, `../../../etc/shadow`, `..\..\windows\win.ini`.
- **Response Inspected**: Substring check for `TRAVERSAL_SIGNATURES`: `["root:x:0:0", "daemon:x:", "[boot loader]"]`.
- **Positive Condition**: Any signature string present in the response body.
- **Evidence Stored**: `"Filesystem signature '{sig}' found in response"`.
- **Exploitability Verification**: **Stronger than XSS/SQLi**. Requiring `"root:x:0:0"` prevents naive reflection false positives because the payload string itself does not contain `"root:x:0:0"`.
- **Severity & CWE**: High, CWE-22, CVSS 7.5.
- **False-Positive Conditions**:
  1. Documentation/Tutorial pages: Educational websites discussing Linux user accounts or `/etc/passwd` formats that naturally contain the string `root:x:0:0`.
- **False-Negative Conditions**:
  1. Non-standard paths: Traversal reading application source code, `.env` files, web configuration files, or non-root user records.
  2. Encoding variations: URL-encoded traversal (`%2e%2e%2f`), double-encoded traversal (`%252e%252e%252f`), or null-byte termination (`%00`) are not tested.
  3. Absolute path injection (e.g. `/etc/passwd` directly without `../`).

---

### 1.4 Security Headers & Configuration
- **Files**: `backend/scanner/stages/probe.py` (`_header_checks`, `_passive_checks`, lines 800-858); `backend/scanner/stages/passive.py`.
- **Input Tested**: HTTP response headers on target root and crawled URLs.
- **Headers Inspected**: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`.
- **Positive Condition**: Header missing from HTTP response.
- **Evidence Stored**: Header name and recommended baseline policy.
- **Exploitability Verification**: Observations only. `probe.py` lines 86, 118 explicitly attempts to suppress security-header noise from active findings, delegating them to passive telemetry.
- **Severity & CWE**: Low / Informational, CWE-693.
- **False-Positive Conditions**:
  1. API Endpoints: Flagging missing `X-Frame-Options` on non-HTML JSON API endpoints where framing is non-applicable.
  2. Upstream WAF/CDN: Scanning origin ports behind reverse proxies that terminate TLS and inject headers at the edge.

---

### 1.5 Open Redirect
- **Files**: `backend/scanner/stages/probe.py` (`_test_open_redirect`, lines 536-566).
- **Input Tested**: Query parameters containing terms like `url`, `redirect`, `next`, `return`.
- **Payloads Sent**: `https://example.com`, `//example.com`.
- **Response Inspected**: HTTP status `301`, `302`, `303`, `307`, `308` and `Location` response header.
- **Positive Condition**: `Location` header starts with or contains the external test domain.
- **Evidence Stored**: Value of `Location` header.
- **Exploitability Verification**: High; checks actual redirection target.
- **False-Positive Conditions**: Target reflects `example.com` in internal path (e.g. `/error?dest=example.com`).

---

### 1.6 Server-Side Template Injection (SSTI)
- **Files**: `backend/scanner/stages/probe.py` (`_test_ssti`, lines 567-595).
- **Input Tested**: Query parameters.
- **Payloads Sent**: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`.
- **Response Inspected**: String match for evaluation result `49`.
- **Positive Condition**: Body contains `49` and did not contain `49` in baseline response.
- **False-Positive Conditions**: Pages where parameter input triggers a legitimate item count, pagination, or price reflecting `49`.

---

## 2. False-Positive Analysis Matrix

| Detector | False-Positive Condition | Current Protection in Code | Severity | Classification |
|---|---|---|---|---|
| **Reflected XSS** | Reflection inside `application/json` or encoded HTML attributes | None in `probe.py`; `scorer.py` evaluates context if artifact exists | High | **CONFIRMED FALSE POSITIVE** |
| **SQL Injection (Boolean)** | Page length variations (>125 chars) due to dynamic banners, CSRF tokens, or timestamps | Modulo 25 length quantization (insufficient) | Critical | **CONFIRMED FALSE POSITIVE** |
| **SQL Injection (Error)** | Generic database error text on input without injection exploitability | Requires matching strings in `SQLI_ERRORS` list | High | **LIKELY FALSE POSITIVE** |
| **Path Traversal** | Educational or doc pages containing `root:x:0:0` in static body | Requires exact signature match | High | **THEORETICAL RISK** |
| **SSTI** | Arithmetic result `49` appears naturally on page (e.g., price, quantity) | Baseline check (checks if `49` was in baseline) | High | **LIKELY FALSE POSITIVE** |
| **Form Probes (Shadowed def 3)** | Reflection of `' OR '1'='1'` treated as SQL Injection | Overwritten by def 4; latent risk if reordered | High | **CONFIRMED FALSE POSITIVE** |
| **Security Headers** | Missing CSP/HSTS on static images or pure JSON API endpoints | Suppressed to passive telemetry in standard mode | Low | **LIKELY FALSE POSITIVE** |
| **Open Redirect** | Relative redirect incorporating domain name as path parameter | Inspects `Location` header | Medium | **THEORETICAL RISK** |

---

## 3. False-Negative Analysis Matrix

| Attack Surface | Failure Mechanism in Code | Impacted Vulnerabilities | Root Cause |
|---|---|---|---|
| **Parameterized URLs** | `f"{url}?{param}={payload}"` produces double `?` syntax | XSS, SQLi, Traversal, SSTI, Open Redirect | Query string parsing omitted |
| **Single Page Applications (SPAs)** | Playwright worker crashes on launch due to missing Node CLI driver | All DOM & Dynamic Endpoint vulnerabilities | Unhandled environment failure |
| **JSON REST APIs** | Prober only transmits `GET` query parameters and form urlencoded bodies | SQLi, Command Injection, SSRF in JSON endpoints | JSON body mutation not supported in `probe.py` |
| **WAF / Filter Evasion** | Raw `<script>` tags sent without URL encoding | Reflected XSS | Payloads blocked by upstream reverse proxies |
| **Blind Injections** | Zero time-delay (`sleep(5)`) probe logic in active probe stage | Blind SQLi, Blind Command Injection | Only error and length checks implemented |
| **Multi-Stage State Changes** | Form probes only execute single-step POST without session tokens | CSRF, Multi-step Business Logic Flaws | Sequential state flow missing in default crawler |

---

## 4. Evidence & Verification Quality

1. **Evidence Persistence Disconnect**:
   - `backend/scanner/stages/probe.py` detects issues and returns raw dictionaries with human-readable summary strings (e.g., `"evidence": "SQL error string detected: 'syntax error'"`).
   - It **does not persist raw HTTP request or response wire bytes** to `EvidenceArtifact` during the probe run.
   - Consequently, when findings reach `backend/api/models.py`, they cannot satisfy the `evidence_artifact_ids` invariant and are forcibly downgraded to `Tentative`.
2. **Reproduction Quality**:
   - `backend/reporting/github_issues.py` contains `build_reproduction_curl`, which generates a reproducible `curl` command.
   - However, because the original probe URLs are often malformed with double `?` syntax, the generated `curl` command reproduces the malformed request rather than the true exploit vector.
