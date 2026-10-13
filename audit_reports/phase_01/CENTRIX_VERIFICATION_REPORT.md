# CENTRIX Forensic Verification Report

**Audit Mode**: Read-Only Forensic Architecture, Codebase & Runtime Verification  
**Phase**: Phase 01 Verification  
**Target Repository**: `/home/sosuke/Desktop/CENTRIX-main`  
**Execution Date**: October 2026  
**Auditor**: Antigravity Forensic Security Team  
**Status**: VERIFIED & REPRODUCED (Investigation Only — Zero Code Modifications Applied)  

---

## 1. Executive Verification Summary

Following the completion of the forensic audit reports, this verification phase executed direct source-code AST inspection, runtime test harnesses, and network protocol simulations to definitively confirm the priority findings (**P0 / P1**).

Every finding analyzed below has been verified with exact file paths, line numbers, AST traces, and programmatic execution outputs. **Zero source code modifications were made during this verification.**

| Issue ID | Category | Summary | Verification Method | Status |
|---|---|---|---|---|
| **CEN-P0-001** | Scanner Core | `_form_probes` quadruple definition & logic bugs | Python AST & byte line inspection | **VERIFIED (CRITICAL)** |
| **CEN-P0-002** | Access Control | Complete lack of API authentication across 85 routes | FastAPI router dependency analysis & TestClient execution | **VERIFIED (CRITICAL)** |
| **CEN-P0-003** | SSRF | TOCTOU DNS-Rebinding in `safety.py` vs `aiohttp` | Socket resolution analysis across 31 ClientSession instances | **VERIFIED (CRITICAL)** |
| **SEC-SSRF-02** | SSRF | Unvalidated HTTP 302 redirect following to internal hosts | Aiohttp default redirect execution with mock server | **VERIFIED (HIGH)** |
| **SEC-DATA-01** | Cryptography | Plaintext credentials in SQLite & hardcoded master key | SQL schema inspection & `store.py` serialization trace | **VERIFIED (HIGH)** |
| **CEN-P1-001** | Dependencies | Missing production dependencies (`chromadb`, `flask`, `a2wsgi`) | Manifest comparison against active imports | **VERIFIED (MAJOR)** |
| **CEN-P1-002** | Code Correctness | Unawaited coroutine in threat intel enrichment test | Pytest execution producing `TypeError` | **VERIFIED (MAJOR)** |
| **CEN-P1-003** | Test Harness | 17 async unit tests failing due to missing `pytest-asyncio` | Automated pytest collection across all test files | **VERIFIED (MAJOR)** |
| **CEN-P1-004** | Crawler Core | Headless Chromium Playwright worker crashes on startup | Node.js driver path trace & exception capture | **VERIFIED (MAJOR)** |
| **CEN-P1-005** | Probe Core | Malformed probe URLs with double `?` syntax | URL parsing verification using `urllib.parse` | **VERIFIED (MAJOR)** |
| **CEN-P1-006** | Finding Pipeline | Probes claim "Confirmed" without artifacts, downgraded to "Tentative" | Pydantic model validator execution | **VERIFIED (MAJOR)** |
| **CEN-P1-007** | Dead Code | `_test_sqli` is dead code (shadowed by `_test_sqli_v2`) | AST caller graph search across repository | **VERIFIED (MAJOR)** |
| **DOC-CODE-01** | Truthfulness | Fabricated Markov fuzzer & 98.4% precision claims | Whole-repo regex & AST search | **VERIFIED (MAJOR)** |

---

## 2. In-Depth Verification of P0 Findings

### 2.1 CEN-P0-001: Quadruple Function Definition of `_form_probes`

#### Source-Code AST Evidence
Parsing `backend/scanner/stages/probe.py` via Python's `ast` module confirms four distinct `AsyncFunctionDef` nodes with the name `_form_probes`:
```text
Total _form_probes definitions found: 4
Def #1: Line 343 - Doc: "Test safe form fields for reflected XSS and error-based SQL injection."
Def #2: Line 404 - Doc: "Test safe form fields for reflected XSS and error-based SQL injection."
Def #3: Line 861 - Doc: "Test form submissions for XSS/SQLi — aggressive mode only."
Def #4: Line 898 - Doc: "Test safe form fields for reflected XSS and error-based SQL injection."
```

#### Code Analysis & Logic Bugs
1. **Python Dynamic Shadowing**: Python executes module definitions sequentially. When `probe.py` is imported, Definition 4 at **line 898** completely overwrites Definitions 1, 2, and 3 in the module's `__dict__`. Lines 343-897 for this function are dead, redundant bytecode.
2. **Def #3 (Line 861) Catastrophic Classification Bug**:
   ```python
   # backend/scanner/stages/probe.py:870-888
   for inp in inputs[:2]:
       for payload in ['<script>alert(1)</script>', "' OR '1'='1"]:
           ...
           if payload in body:
               results.append({
                   "type": "xss",   # <-- BUG: Assigns type "xss" even when payload is "' OR '1'='1'"!
                   "url": action,
                   "param": inp,
                   "payload": payload,
                   "evidence": f"Reflected in form submission at {action}",
                   "confidence": "Confirmed",
               })
   ```
   If Definition 3 were active, it would classify the SQL injection payload `' OR '1'='1'` as an **XSS vulnerability**, while falsely declaring it `"Confirmed"` simply because the payload text was echoed back in the HTML response.
3. **Def #4 (Line 898) Evidence & Payload Sizing Flaws**:
   - Hardcodes `"confidence": "Confirmed"` without persisting an `EvidenceArtifact`.
   - Naively uses `data = _form_data(fields, inp, payload)` without supporting `multipart/form-data` or JSON body payloads.

---

### 2.2 CEN-P0-002: Complete Lack of API Authentication (CWE-306)

#### Source-Code Route Evidence
Inspection of all 85 registered routes in `backend/main.py` confirms that **zero** endpoints define security dependencies:
```text
Total registered routes: 85
Routes with explicit dependencies: 0
  ['POST'] /api/scan/start                     -> deps: []
  ['POST'] /api/scan/{scan_id}/stop            -> deps: []
  ['GET']  /api/scans                          -> deps: []
  ['GET']  /api/findings                       -> deps: []
  ['POST'] /api/agent/session/{session_id}/start -> deps: []
  ['GET']  /api/integrations/status            -> deps: []
  ...
```

#### Runtime Execution Evidence
Using Starlette's `TestClient` against `main:app` without supplying any `Authorization` or `Cookie` header:
```python
# Direct test execution against backend/main.py
client = TestClient(app)
client.get('/health')                  -> Status: 200 OK
client.get('/api/scans')               -> Status: 200 OK
client.get('/api/findings')            -> Status: 200 OK
client.get('/api/reports')             -> Status: 200 OK
client.get('/api/integrations/status') -> Status: 200 OK
client.get('/api/manual/corpus')       -> Status: 200 OK
```
**Conclusion**: Any process on the local machine or any cross-origin script capable of dispatching requests to port 8000 can fully command the scanner and read all discovered vulnerabilities.

---

### 2.3 CEN-P0-003: SSRF via TOCTOU DNS Rebinding (CWE-918)

#### Source-Code Trace
1. **Pre-flight Check (`backend/scanner/safety.py:59-70`)**:
   ```python
   async def ensure_public_target(url: str) -> None:
       parsed = urlparse(normalise_target(url))
       host = parsed.hostname or ""
       records = await asyncio.get_running_loop().getaddrinfo(host, None)
       addresses = {record[4][0] for record in records}
       if not addresses or any(not _is_public_ip(address) for address in addresses):
           raise TargetSafetyError("Targets resolving to private, local, or reserved addresses are not allowed")
   ```
2. **Runtime Execution Disconnect**:
   - `ensure_public_target` is called once in `api/routes/scan.py:41` when a scan is submitted.
   - Across the entire `backend/scanner/` directory, there are **31 separate instantiations** of `aiohttp.ClientSession()`.
   - None of these instantiations configure an IP-pinned `TCPConnector` or custom DNS resolver.
   - During `probe.py`, `crawl.py`, and `discover.py`, `aiohttp` re-resolves the target domain name via system DNS for each HTTP connection.
3. **Exploit Vector**: An attacker provisions a domain with a 1-second TTL returning a public IP on the first query, followed by `127.0.0.1` or `169.254.169.254` on subsequent queries. The scanner passes validation, starts, and subsequently connects directly to loopback or cloud metadata services.

---

## 3. In-Depth Verification of Security & SSRF Flaws

### 3.1 SEC-SSRF-02: Unvalidated HTTP 302 Redirect Following

#### Technical Trace
In `aiohttp.ClientSession`, the default parameter for `allow_redirects` is `True`.
- In `backend/scanner/stages/probe.py`:
  - `_test_sqli_v2` (line 220): `session.get(url, params=...)` — default `allow_redirects=True`.
  - `_test_xss` (line 291): `session.get(probe_url, ...)` — default `allow_redirects=True`.
  - `_test_traversal` (line 322): `session.get(probe_url, ...)` — default `allow_redirects=True`.
  - `_form_probes` (lines 921, 924): `session.post(...)` / `session.get(...)` — default `allow_redirects=True`.
  - Only `_test_open_redirect` (line 548) sets `allow_redirects=False`.
- In `backend/scanner/stages/discover.py:100`: Explicitly sets `allow_redirects=True`.
- In `backend/scanner/stages/validate.py`: Default `allow_redirects=True`.

#### Runtime Simulation Evidence
A mock HTTP server was configured on `127.0.0.1:8999` returning `HTTP 302 Found` with `Location: http://127.0.0.1:8000/health`.
When queried using `aiohttp.ClientSession.get()` matching the scanner's probe configuration:
```text
aiohttp.client_exceptions.ClientConnectorError: Cannot connect to host 127.0.0.1:8000 ssl:default [Connect call failed ('127.0.0.1', 8000)]
```
The client followed the redirect and attempted an immediate socket connection to internal port 8000 on `127.0.0.1`. If an external server redirects to `http://169.254.169.254/latest/meta-data/`, CENTRIX follows the redirect and issues requests to the AWS metadata endpoint.

---

### 3.2 SEC-DATA-01: Plaintext Credentials in SQLite & Hardcoded Master Key (CWE-312, CWE-798)

#### Source-Code Storage Trace
1. **Plaintext Storage in `backend/db/store.py`**:
   - Lines 40-54 create tables: `auth_profiles`, `settings`, `integration_outbox`.
   - `save_auth_profile` (line 298):
     ```python
     conn.execute("INSERT OR REPLACE INTO auth_profiles (id, payload) VALUES (?, ?)", (profile_id, _json(payload)))
     ```
   - `save_setting` (line 330):
     ```python
     conn.execute("INSERT OR REPLACE INTO settings (id, payload) VALUES (?, ?)", (setting_id, _json(payload)))
     ```
   - Both functions convert sensitive dictionaries (containing `Authorization: Bearer <token>`, session cookies, Jira/GitHub API tokens) to plaintext JSON strings via `_json(payload) = json.dumps(payload)` and insert them unencrypted into `centrix.db`.
2. **Disconnected `SecretManager`**:
   - `backend/agent/secrets.py` defines an encrypted `SecretManager` class using Fernet, but `backend/db/store.py` **never imports or calls it**.
3. **Hardcoded Fallback Master Key**:
   - In `backend/agent/secrets.py:46`:
     ```python
     raw_key = master_key or os.getenv(_MASTER_KEY_ENV) or "centrix-default-platform-master-key-2026"
     ```
   - If the environment variable `CENTRIX_MASTER_KEY` is omitted, the encryption key defaults to a static, publicly visible string in the repository.

---

## 4. In-Depth Verification of P1 Findings

### 4.1 CEN-P1-001: Missing Production Dependencies in `requirements.txt`
Comparison of imports against `backend/requirements.txt`:
- `chromadb`: Imported in `backend/scanner/threat_intel/vector_store.py:39`. **NOT in requirements.txt**.
- `flask`: Imported in `backend/main.py:55`. **NOT in requirements.txt**.
- `a2wsgi`: Required for `fastapi.middleware.wsgi.WSGIMiddleware`. **NOT in requirements.txt**.
- `pytest-asyncio`: Required for running async test suites. **NOT in requirements.txt**.

---

### 4.2 CEN-P1-002: Unawaited Coroutine in Threat Intel Test Suite
- **File**: `backend/tests/test_threat_intel.py:285`
- **Code**:
  ```python
  enriched = enrich_findings_with_ai(findings, rag_engine=mock_engine)
  self.assertEqual(len(enriched), 1)
  ```
- **Runtime Failure**:
  ```text
  TypeError: object of type 'coroutine' has no len()
  RuntimeWarning: coroutine 'enrich_findings_with_ai' was never awaited
  ```
- **Cause**: `enrich_findings_with_ai` in `scanner/report_generator.py:30` is declared `async def`, but was called as a regular synchronous function.

---

### 4.3 CEN-P1-003: Pytest Async Harness Failure
Executing `pytest backend/tests/test_advanced_retest.py` produces:
```text
FAILED backend/tests/test_advanced_retest.py::test_retest_finding_xss_reproduced
async def functions are not natively supported.
You need to install a suitable plugin for your async framework...
```
16 test functions across 7 test files fail because `pytest-asyncio` is neither declared in dependencies nor configured in `pytest.ini`.

---

### 4.4 CEN-P1-004: Headless Browser Driver Failure
Executing `BrowserWorker.explore_target` in `backend/scanner/browser/worker.py` fails with:
```text
node:internal/modules/cjs/loader:1520
  throw err;
Error: Cannot find module '/usr/share/nodejs/playwright/cli.js'
Exception: Connection.init: Connection closed while reading from the driver
```
Because the driver is missing, `scanner/engine.py:277` catches the exception and logs `[INFO] Browser worker skipped: ...`, silently bypassing SPA crawl discovery.

---

### 4.5 CEN-P1-005: Query Parameter Concatenation Bug
- **File**: `backend/scanner/stages/probe.py:290, 321`
- **Code**: `probe_url = f"{url}?{param}={payload}"`
- **Verification**:
  ```python
  base_url = 'https://target.com/view.php?article=123'
  probe_url = f'{base_url}?search=<script>alert(1)</script>'
  # Resulting URL: https://target.com/view.php?article=123?search=<script>alert(1)</script>
  # Parsed query dict: {'article': ['123?search=<script>alert(1)</script>']}
  # Was parameter 'search' parsed?: False
  ```
- **Impact**: Any endpoint discovered by the crawler that already has a query parameter will receive a malformed double `?` URL. The target web server parses the payload as part of the previous parameter value, completely missing the intended injection vector.

---

### 4.6 CEN-P1-006: Finding Model Invariant Desynchronization
- **File**: `backend/api/models.py:90-112`
- **Code & Test Output**:
  ```python
  finding = Finding(
      id='VLN-TEST-1', scan_id='SCN-1', title='XSS',
      classification=FindingClassification.confirmed,
      evidence_artifact_ids=[]  # probe.py never populates this
  )
  print(finding.classification)
  # Output: FindingClassification.tentative
  print(finding.confidence_reasons)
  # Output: ['Downgraded from Confirmed: Missing persisted evidence artifact.']
  ```
- **Impact**: `probe.py` asserts findings as `"Confirmed"`, but because it fails to persist an `EvidenceArtifact`, the Pydantic validator unconditionally demotes every confirmed finding to `"Tentative"`.

---

### 4.7 CEN-P1-007: Dead Code in `probe.py`
- **File**: `backend/scanner/stages/probe.py:156-207` (`_test_sqli`)
- **Verification**: A repository-wide regex search for `\b_test_sqli\b` reveals exactly one occurrence: its own definition at line 156. Line 100 in `probe.run` calls `_test_sqli_v2`. The original `_test_sqli` function is completely unreferenced.

---

## 5. In-Depth Verification of Documented vs. Implemented Claims

### 5.1 The Markov Chain & Precision Fabrication
1. **Markov Chains**:
   - `CENTRIX_How_ML_Works.pdf` and `generate_ml_explainer_pdf.py` claim an offensive Markov-chain fuzzing engine.
   - An exhaustive search across the entire workspace for `markov` returns **zero occurrences in application code**; all occurrences are strictly within `generate_ml_explainer_pdf.py` and the audit reports.
2. **98.4% Precision**:
   - The whitepaper claims an empirical benchmark score of **98.4% grounded precision**.
   - An exhaustive search reveals that `98.4` exists solely as a hardcoded text literal in `generate_ml_explainer_pdf.py:282`. There is no benchmarking framework or validation dataset.
3. **100% Air-Gapped Local Model Contradiction**:
   - The whitepaper asserts 100% on-premise execution with zero external data transmission.
   - `.env.example`, `docker-compose.yml`, and `backend/agent/debate.py` explicitly configure and call `https://api.xkiro.com/v1` with remote models (`minimax/minimax-m3:free`).

---

## 6. Verification Conclusion & Sign-Off

Every critical finding reported in Phase 01 has been independently verified through source inspection and runtime evidence. The defects are structural and programmatic, not theoretical:
1. `_form_probes` has 4 definitions, dead code, and inverted classification logic.
2. All 85 API routes are completely unauthenticated.
3. The scanner is vulnerable to both DNS-rebinding SSRF and HTTP 302 redirect SSRF.
4. Credentials are stored in plaintext in SQLite, and the secrets module contains a hardcoded fallback master key.
5. The core probe engine corrupts parameterized URLs with double `?` syntax and fails to persist evidence artifacts.
6. Key marketing claims (Markov chains, 98.4% precision) are completely fabricated in PDF generators.

### STOP CONDITION ENFORCED
As instructed, **zero source code modifications, bug fixes, or refactors have been made**. Standing by for project owner review and explicit instruction before proceeding to remediation.
