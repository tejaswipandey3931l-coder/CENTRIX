# CENTRIX Technical Issue Register

**Audit Mode**: Read-Only Forensic Architecture, Codebase & Runtime Audit  
**Phase**: Phase 01  
**Total Issues Logged**: 17  
- **Confirmed P0 (Critical)**: 3  
- **Confirmed P1 (Major)**: 7  
- **Confirmed P2 (Moderate)**: 5  
- **Confirmed P3 (Minor)**: 2  

---

### Issue ID: CEN-P0-001
- **Priority**: P0 (Critical)
- **Component**: DAST Probe Engine
- **File**: `backend/scanner/stages/probe.py`
- **Function**: `_form_probes`
- **Line**: 343, 404, 861, 898
- **Problem**: Quadruple definition of the function `_form_probes` in the same module file.
- **Expected behaviour**: A single, robust, authoritative implementation of `_form_probes` that handles form discovery, field filtering, payload injection, and evidence generation.
- **Actual behaviour**: Python silently overwrites previous definitions upon file evaluation. The 4th definition at line 898 shadows definitions at lines 343, 404, and 861. In definition 3 (line 861), SQL injection was checked via `if payload in body`, which treats SQL payload reflection as SQL injection! In definition 4 (line 898), results are appended with hardcoded `"confidence": "Confirmed"` but no `evidence_artifact_ids` are attached.
- **Root cause**: Merge pollution and uncontrolled copy-pasting of legacy code blocks into `probe.py` without code review.
- **Impact**: Breaks form-based vulnerability scanning consistency; introduces silent logic regressions depending on which duplicate is active; causes severe false-positive logic if earlier definitions are ever reordered.
- **Evidence**: AST inspection and line examination confirm 4 identical function signatures in `backend/scanner/stages/probe.py`.
- **Reproduction**: Run `python -c "import ast; tree = ast.parse(open('backend/scanner/stages/probe.py').read()); print([n.lineno for n in tree.body if isinstance(n, ast.AsyncFunctionDef) and n.name == '_form_probes'])"` -> Outputs `[343, 404, 861, 898]`.
- **False positive/negative relevance**: Definition 3 produces 100% false positives for SQLi (flags `' OR '1'='1'` simply when reflected in an input confirmation page).
- **Recommended correction**: Remove the 3 redundant definitions at lines 343, 404, and 861. Unify into a single well-tested `_form_probes` function that creates linked `EvidenceArtifact` records.
- **Required regression test**: Test form submission parser with parameterized inputs and verify exact execution path in `tests/test_probe_forms.py`.
- **Confidence**: 10/10
- **Status**: CONFIRMED

---

### Issue ID: CEN-P0-002
- **Priority**: P0 (Critical)
- **Component**: API Security / Access Control
- **File**: `backend/main.py`, `backend/api/routes/*`
- **Function**: All route handlers
- **Line**: 1-121 in `backend/main.py`
- **Problem**: Entire REST and WebSocket API surface has zero authentication or authorization enforcement.
- **Expected behaviour**: All administrative endpoints (`/api/scan/start`, `/api/scan/{id}/stop`, `/api/agent/*`, `/api/findings/*`, `/api/integrations/*`) require an API key, session cookie, or Bearer token.
- **Actual behaviour**: Any client capable of reaching `http://localhost:8000` or sending cross-origin requests can start scans, stop scans, read all security findings, download reports, or execute agent actions without authentication.
- **Root cause**: No authentication middleware, dependency injection (`Depends(get_current_user)`), or token verification was ever implemented in FastAPI routes.
- **Impact**: Unauthenticated remote or local attackers can hijack the scanner, trigger unauthorized DAST attacks against arbitrary targets (causing legal liability for the user), exfiltrate vulnerability data, and access third-party integration secrets (Jira/GitHub tokens).
- **Evidence**: Direct inspection of `backend/api/routes/scan.py`, `findings.py`, `reports.py`, `agent.py`, `integrations.py` shows no auth dependencies.
- **Reproduction**: Send `curl -X POST http://localhost:8000/api/scan/start -H "Content-Type: application/json" -d '{"target":"https://example.com","authorized":true}'` -> Accepted and executed without credentials.
- **False positive/negative relevance**: N/A (Security Architecture).
- **Recommended correction**: Implement a robust API key or JWT Bearer authentication scheme with granular role-based permissions (`admin`, `analyst`, `read-only`).
- **Required regression test**: Ensure all API routes return HTTP 401 Unauthorized when requested without valid authentication headers.
- **Confidence**: 10/10
- **Status**: CONFIRMED

---

### Issue ID: CEN-P0-003
- **Priority**: P0 (Critical)
- **Component**: Safety & SSRF Guardrails
- **File**: `backend/scanner/safety.py`
- **Function**: `ensure_public_target`
- **Line**: 59-70
- **Problem**: Target IP safety check is subject to Time-of-Check to Time-of-Use (TOCTOU) DNS Rebinding attack.
- **Expected behaviour**: The scanner should resolve the target hostname to an IP, verify the IP is public/global, and bind all subsequent HTTP requests directly to that resolved IP address (using a custom DNS resolver or connection pool pinning).
- **Actual behaviour**: `ensure_public_target` resolves the hostname once during initial scan setup. The actual scanner requests made in `aiohttp.ClientSession` perform independent DNS lookups per request without IP pinning or subsequent validation.
- **Root cause**: Disconnection between initial target pre-flight validation and runtime HTTP request dispatching.
- **Impact**: An attacker configuring a malicious DNS domain (which returns a public IP initially and resolves to `127.0.0.1` or `169.254.169.254` on subsequent queries) can force CENTRIX to probe internal services and AWS/GCP metadata endpoints (Full SSRF).
- **Evidence**: `ensure_public_target` only executes in `api/routes/scan.py:41` at start. `scanner/stages/probe.py` and `crawl.py` create raw `aiohttp.ClientSession()` calls passing URLs directly without socket pinning.
- **Reproduction**: Configure dual-A record or short TTL rebinding domain `attacker.com` -> Setup passes pre-flight check, then scanner hits internal services.
- **False positive/negative relevance**: High risk of false findings on internal networks or unintended internal DoS.
- **Recommended correction**: Implement custom `aiohttp.TCPConnector` with an address resolver that validates every resolved IP address against RFC1918/RFC3927/loopback before socket connection.
- **Required regression test**: Test `TCPConnector` with simulated DNS rebinding host resolving to `127.0.0.1` and assert connection rejection.
- **Confidence**: 9/10
- **Status**: CONFIRMED

---

### Issue ID: CEN-P1-001
- **Priority**: P1 (Major)
- **Component**: Dependency Management & Runtime Environment
- **File**: `backend/requirements.txt`
- **Function**: Package Manifest
- **Line**: 1-15
- **Problem**: Core runtime dependencies used in production code are missing from `requirements.txt`.
- **Expected behaviour**: All packages imported by the backend (`chromadb`, `flask`, `a2wsgi`, `pytest-asyncio`) must be declared in `requirements.txt`.
- **Actual behaviour**: `requirements.txt` only lists 14 packages. `chromadb` (required by `vector_store.py`), `flask` and `a2wsgi` (required by `main.py:53-71`), and `pytest-asyncio` are omitted.
- **Root cause**: Incomplete dependency tracking when new features were committed to the repository.
- **Impact**: Docker builds fail to provide RAG capability; mounting of threat intel Flask blueprints fails with warnings; tests fail out-of-the-box on fresh environments.
- **Evidence**: `backend/main.py:54` imports `fastapi.middleware.wsgi.WSGIMiddleware` and `flask.Flask`. `backend/scanner/threat_intel/vector_store.py:39` imports `chromadb`. Neither is in `backend/requirements.txt`.
- **Reproduction**: Run `pip install -r backend/requirements.txt` in a clean Python environment and run `python backend/main.py` -> Threat intel blueprint import raises `ImportError`.
- **False positive/negative relevance**: N/A.
- **Recommended correction**: Add `chromadb`, `flask`, `a2wsgi`, and test requirements (`pytest`, `pytest-asyncio`) to `requirements.txt`.
- **Confidence**: 10/10
- **Status**: CONFIRMED

---

### Issue ID: CEN-P1-002
- **Priority**: P1 (Major)
- **Component**: Threat Intel Enrichment / Test Suite
- **File**: `backend/scanner/report_generator.py` and `backend/tests/test_threat_intel.py`
- **Function**: `enrich_findings_with_ai` / `TestThreatIntel.test_report_enrichment_and_warnings`
- **Line**: `report_generator.py:30`, `test_threat_intel.py:285`
- **Problem**: `enrich_findings_with_ai` is an `async def` function, but is invoked synchronously without `await` in tests.
- **Expected behaviour**: Asynchronous functions must be awaited or executed via an async event loop runner.
- **Actual behaviour**: In `test_threat_intel.py:285`, `enriched = enrich_findings_with_ai(...)` is called synchronously. The return value is a coroutine object, not a list, causing `TypeError: object of type 'coroutine' has no len()` and test failure.
- **Root cause**: Signature was converted from synchronous to async in `report_generator.py` without updating callers in unit tests.
- **Impact**: Unit test suite fails on `test_threat_intel.py`; unhandled coroutines can leak across the runtime if called incorrectly by external scripts.
- **Evidence**: `pytest tests/test_threat_intel.py -k test_report_enrichment_and_warnings` fails with `TypeError: object of type 'coroutine' has no len()`.
- **Reproduction**: Run `pytest tests/test_threat_intel.py:TestThreatIntel.test_report_enrichment_and_warnings`.
- **False positive/negative relevance**: N/A.
- **Recommended correction**: Update test to use `asyncio.run(enrich_findings_with_ai(...))` or mark test with async runner.
- **Confidence**: 10/10
- **Status**: CONFIRMED

---

### Issue ID: CEN-P1-003
- **Priority**: P1 (Major)
- **Component**: Test Suite Harness
- **File**: `backend/tests/test_*.py`
- **Function**: 16 async test functions across 7 test files
- **Line**: Various
- **Problem**: Pytest cannot execute async test functions due to missing async runner plugin.
- **Expected behaviour**: All unit tests execute cleanly and report pass/fail status.
- **Actual behaviour**: Running `pytest backend/tests/` results in immediate failure for 16 async tests with: `async def functions are not natively supported. You need to install a suitable plugin for your async framework...`.
- **Root cause**: `pytest-asyncio` is not configured in pytest ini / pyproject.toml and not installed in standard virtual environment.
- **Impact**: Automated CI/CD pipelines break; regression test execution is impossible without external test runner shims.
- **Evidence**: Pytest run on `test_advanced_retest.py`, `test_agent_system.py`, `test_browser_worker.py`, `test_live_connectors.py`, `test_retest_and_diff.py`, `test_state_machine_recovery.py`, `test_safety_guardrails.py` all fail with identical error.
- **Reproduction**: Run `pytest backend/tests/test_advanced_retest.py`.
- **Confidence**: 10/10
- **Status**: CONFIRMED

---

### Issue ID: CEN-P1-004
- **Priority**: P1 (Major)
- **Component**: Dynamic SPA Crawler
- **File**: `backend/scanner/browser/worker.py`
- **Function**: `BrowserWorker.explore_target`
- **Line**: 40-75
- **Problem**: Playwright worker crashes when launched because the Node.js CLI driver is missing.
- **Expected behaviour**: Playwright launches headless Chromium, navigates the SPA, and returns discovered DOM routes and forms.
- **Actual behaviour**: Playwright raises: `Error: Cannot find module '/usr/share/nodejs/playwright/cli.js'` followed by `Exception: Connection.init: Connection closed while reading from the driver`.
- **Root cause**: In Linux environment, `playwright install` was executed without installing the underlying Node driver and browser binaries in system path.
- **Impact**: SPA discovery is silently skipped in every scan (`scanner/engine.py:277`); dynamic JavaScript routes and AJAX forms are never discovered, causing massive false negatives on modern web applications.
- **Evidence**: Runtime execution log of `test_browser_worker` and task-192 logs show `MODULE_NOT_FOUND`.
- **Reproduction**: Run `python -c "from scanner.browser.worker import browser_worker; import asyncio; asyncio.run(browser_worker.explore_target('https://example.com'))"`.
- **False positive/negative relevance**: Severe false-negative risk for all Angular, React, Vue applications.
- **Recommended correction**: Ensure `playwright install --with-deps` is properly scripted and add a health-check validator that gracefully falls back if browser driver is offline.
- **Confidence**: 10/10
- **Status**: CONFIRMED

---

### Issue ID: CEN-P1-005
- **Priority**: P1 (Major)
- **Component**: DAST Probe Engine
- **File**: `backend/scanner/stages/probe.py`
- **Function**: `_test_xss`, `_test_traversal`
- **Line**: 290, 321
- **Problem**: Probe URL construction uses naive string interpolation causing malformed URLs with double question marks and unencoded characters.
- **Expected behaviour**: Query parameters should be parsed and updated using `urllib.parse.urlencode` or `yarl.URL`.
- **Actual behaviour**: `probe_url = f"{url}?{param}={payload}"` is executed. If `url` already contains query parameters (e.g. `https://target.com/page?id=1`), the generated probe URL is `https://target.com/page?id=1?param=<script>alert(1)</script>`.
- **Root cause**: Failure to use standard URL manipulation libraries.
- **Impact**: Servers reject malformed query strings with 400 Bad Request or fail to parse `param`, causing the vulnerability detector to never test the intended parameter (100% false negative on parameterized URLs).
- **Evidence**: `backend/scanner/stages/probe.py:290`: `probe_url = f"{url}?{param}={payload}"`.
- **Reproduction**: Trace probe URL generation with input `url = "http://example.com/api?user=1"`, `param = "q"`, `payload = "test"`.
- **False positive/negative relevance**: Direct cause of widespread false negatives.
- **Recommended correction**: Use `urllib.parse.urlsplit`, `parse_qsl`, and `urlencode` to construct query parameters.
- **Confidence**: 10/10
- **Status**: CONFIRMED

---

### Issue ID: CEN-P1-006
- **Priority**: P1 (Major)
- **Component**: Finding Pipeline & Classification
- **File**: `backend/scanner/stages/probe.py` vs `backend/api/models.py`
- **Function**: `Finding.validate_classification_invariants`
- **Line**: `models.py:90-112`, `probe.py:935`
- **Problem**: Finding pipeline desynchronization: probes claim "Confirmed" without creating evidence artifacts, which the model validator immediately downgrades to "Tentative".
- **Expected behaviour**: Probes that confirm vulnerabilities must create and persist an `EvidenceArtifact` in `store.add_evidence()` and attach its ID to `evidence_artifact_ids`.
- **Actual behaviour**: `probe.py` assigns `"confidence": "Confirmed"` directly to the raw vulnerability dictionary without creating an `EvidenceArtifact`. When `analyze.py` constructs a `Finding` object, the Pydantic validator executes:
  `if self.classification == FindingClassification.confirmed and not self.evidence_artifact_ids: self.classification = FindingClassification.tentative; self.confidence_reasons.append("Downgraded from Confirmed: Missing persisted evidence artifact.")`.
- **Root cause**: Architectural contract breach between probing stage and finding validation model.
- **Impact**: All probe-confirmed vulnerabilities are automatically downgraded to tentative status, confusing analysts and corrupting reporting metrics.
- **Evidence**: Verified by running `python -c "from api.models import Finding, FindingClassification; f = Finding(..., classification=FindingClassification.confirmed); print(f.classification)"` -> Downgraded to `FindingClassification.tentative`.
- **Reproduction**: Create finding with `confirmed` classification and empty `evidence_artifact_ids`.
- **False positive/negative relevance**: Alters confidence scoring and suppresses valid findings in triage.
- **Recommended correction**: Ensure every detector creating a positive match stores the raw HTTP request/response into `EvidenceArtifact` and populates `evidence_artifact_ids`.
- **Confidence**: 10/10
- **Status**: CONFIRMED

---

### Issue ID: CEN-P1-007
- **Priority**: P1 (Major)
- **Component**: DAST Probe Engine
- **File**: `backend/scanner/stages/probe.py`
- **Function**: `_test_sqli`
- **Line**: 156-207
- **Problem**: Dead/unreachable code: `_test_sqli` is completely uncalled in the active scanning pipeline.
- **Expected behaviour**: Every detection function in `probe.py` should be either actively utilized or removed.
- **Actual behaviour**: `probe.run` only calls `_test_sqli_v2`. The original `_test_sqli` function remains in the module as dead code, confusing auditors and developers.
- **Root cause**: Version 2 of the function was implemented without deleting or deprecating the legacy version.
- **Impact**: Increases maintenance burden and risk of accidental regression if legacy function is re-imported.
- **Evidence**: `probe.py:100` calls `_test_sqli_v2`. A grep for `_test_sqli(` across the entire workspace shows zero other callers.
- **Reproduction**: Run `git grep "_test_sqli("` -> Only definition found.
- **False positive/negative relevance**: N/A.
- **Recommended correction**: Remove `_test_sqli` and consolidate unit tests to `_test_sqli_v2`.
- **Confidence**: 10/10
- **Status**: CONFIRMED

---

### Issue ID: CEN-P2-001
- **Priority**: P2 (Moderate)
- **Component**: Database Storage Layer
- **File**: `backend/db/store.py`
- **Function**: All database helper functions (`get_scan`, `list_scans`, `add_finding`)
- **Line**: 27-150
- **Problem**: Synchronous blocking SQLite file operations executed directly inside async coroutines.
- **Expected behaviour**: Async database access should use an async SQLite library like `aiosqlite` or wrap synchronous blocking database calls in `asyncio.to_thread`.
- **Actual behaviour**: `store.py` opens `sqlite3.connect(_db_path)` synchronously inside `async def get_scan()`, `async def list_scans()`, etc.
- **Root cause**: Naive async wrapper around standard blocking library `sqlite3`.
- **Impact**: Under high concurrency or during massive finding ingestion, the main Python event loop is blocked, causing WebSocket disconnects, dropped scan progress events, and UI freezing.
- **Evidence**: Code inspection of `backend/db/store.py:27` confirms standard `sqlite3.connect` inside `async def` methods.
- **Reproduction**: Launch 50 concurrent `get_scan` calls under heavy disk write load -> asyncio event loop delay spikes.
- **False positive/negative relevance**: N/A.
- **Recommended correction**: Migrate `store.py` to `aiosqlite` or use `asyncio.to_thread`.
- **Confidence**: 9/10
- **Status**: CONFIRMED

---

### Issue ID: CEN-P2-002
- **Priority**: P2 (Moderate)
- **Component**: Code Quality / Future Compatibility
- **File**: Multiple (`api/models.py`, `reporting/github_issues.py`, `reporting/jira.py`, `main.py`)
- **Function**: Various
- **Line**: Various
- **Problem**: Widespread use of deprecated `datetime.datetime.utcnow()` causing Python 3.12+ deprecation warnings.
- **Expected behaviour**: Code should use timezone-aware timestamps: `datetime.datetime.now(datetime.timezone.utc)`.
- **Actual behaviour**: Generates dozens of `DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version` during test runs and server execution.
- **Root cause**: Use of legacy datetime API.
- **Impact**: Future Python releases (Python 3.15+) will raise AttributeError, completely breaking the application.
- **Evidence**: Pytest warning logs show repeated `DeprecationWarning` across `github_issues.py`, `jira.py`, and `main.py`.
- **Reproduction**: Run `python -W error -c "import datetime; datetime.datetime.utcnow()"`.
- **False positive/negative relevance**: N/A.
- **Recommended correction**: Replace all occurrences of `datetime.utcnow()` with `datetime.now(timezone.utc)`.
- **Confidence**: 10/10
- **Status**: CONFIRMED

---

### Issue ID: CEN-P2-003
- **Priority**: P2 (Moderate)
- **Component**: Report Generation
- **File**: `backend/reporting/pdf_report.py`
- **Function**: `build_centrix_pdf_report`
- **Line**: 56-58
- **Problem**: Hard runtime crash when attempting to generate PDF reports if `reportlab` is not installed in the active environment.
- **Expected behaviour**: PDF generation gracefully notifies the caller or falls back to an HTML/Markdown report export.
- **Actual behaviour**: Raises unhandled `RuntimeError: reportlab library is required to generate PDF reports. Install it with: pip install reportlab`, causing HTTP 500 errors on API report endpoints and breaking unit tests (`test_wraith_ports.py`).
- **Root cause**: Strict runtime assertion without fallback handling.
- **Impact**: Users attempting to download PDF scan reports experience server error 500.
- **Evidence**: `test_wraith_ports.py::WraithPortTests::test_report_export_helpers_emit_standard_formats` fails with `RuntimeError: reportlab library is required`.
- **Reproduction**: Uninstall reportlab and call `build_centrix_pdf_report(...)`.
- **False positive/negative relevance**: N/A.
- **Recommended correction**: Ensure fallback to HTML report rendering or return structured error response to frontend.
- **Confidence**: 10/10
- **Status**: CONFIRMED

---

### Issue ID: CEN-P2-004
- **Priority**: P2 (Moderate)
- **Component**: Desktop Application
- **File**: `desktop/centrix_desktop.py`
- **Function**: `main`, `start_backend`, `start_frontend`
- **Line**: 1-70
- **Problem**: Desktop application is advertised as a native client bridge, but is merely a 70-line Python script that spawns subprocesses.
- **Expected behaviour**: A packaged desktop client (using Electron, Tauri, or PySide/PyQt) providing an embedded native GUI window.
- **Actual behaviour**: Launches `uvicorn` and `npm run dev` in background subprocesses and opens the default system web browser to `http://127.0.0.1:8443/`.
- **Root cause**: Placeholder scaffold created without desktop framework integration.
- **Impact**: Misleading architectural claim; fragile execution on end-user machines that lack npm/node installed locally.
- **Evidence**: `desktop/centrix_desktop.py` lines 44-52: calls `webbrowser.open("http://127.0.0.1:8443/")`.
- **Reproduction**: Inspect `desktop/centrix_desktop.py`.
- **False positive/negative relevance**: N/A.
- **Recommended correction**: Document `centrix_desktop.py` accurately as a local development launcher script or implement a proper Tauri wrapper.
- **Confidence**: 10/10
- **Status**: CONFIRMED

---

### Issue ID: CEN-P2-005
- **Priority**: P2 (Moderate)
- **Component**: SQLi Vulnerability Detector
- **File**: `backend/scanner/stages/probe.py`
- **Function**: `_test_sqli_v2`, `_fingerprints_different`
- **Line**: 261-278
- **Problem**: SQLi boolean differential analysis uses naive length comparison that triggers false positives on pages with dynamic content.
- **Expected behaviour**: Boolean differential detection must strip dynamic elements (timestamps, anti-CSRF tokens, view counters, random session nonces) before evaluating response similarity.
- **Actual behaviour**: `_response_fingerprint` normalizes body length with `(len(body) // 25) * 25`. `_fingerprints_different` flags difference if length varies by >= 125 chars or 15%.
- **Root cause**: Insufficient HTML DOM normalization before differential comparison.
- **Impact**: Any page whose content dynamically shifts by more than 125 characters (e.g. dynamic rotating articles, live feeds, comment counts) between two requests will trigger a false positive SQL injection finding.
- **Evidence**: `probe.py:277`: `return left[0] != right[0] or abs(left[1] - right[1]) >= max(125, int(max(left[1], right[1]) * 0.15)) or left[2] != right[2]`.
- **Reproduction**: Simulate target endpoint returning random 150-byte strings in responses -> Triggers SQLi Confirmed alert.
- **False positive/negative relevance**: Confirmed False Positive Risk.
- **Recommended correction**: Use structural DOM comparison (e.g. tag tree hash) or extract and compare only textual content after stripping dynamic form fields.
- **Confidence**: 9/10
- **Status**: CONFIRMED

---

### Issue ID: CEN-P3-001
- **Priority**: P3 (Minor)
- **Component**: Documentation / Marketing Claims
- **File**: `generate_ml_explainer_pdf.py`, `CENTRIX_How_ML_Works.pdf`
- **Function**: `_build_page1`, `_build_page2`, `_build_page3`
- **Line**: 124, 138, 228, 282
- **Problem**: Whitepaper generation script fabricates claims regarding Markov-chain fuzzers and 98.4% precision metrics with zero code backing.
- **Expected behaviour**: Technical documentation reflects verified features and empirically measured metrics.
- **Actual behaviour**: Code claims: "Markov-chain payload generators... Offensive statistical ML model generating obfuscated fuzzing & injection payloads" and "Report Accuracy Score: 98.4% grounded precision". No Markov chain code or precision measurement harness exists anywhere in the repository.
- **Root cause**: Marketing and research narrative drafted independently of actual engineering implementation.
- **Impact**: Severely damages project credibility upon technical due diligence or source code audit.
- **Evidence**: Workspace-wide search for `markov` returns only `generate_ml_explainer_pdf.py`. Search for `98.4` returns only the PDF generator.
- **Reproduction**: Grep workspace for `markov`.
- **False positive/negative relevance**: N/A.
- **Recommended correction**: Revise whitepaper generator to document actual heuristic and deterministic algorithms used by the platform.
- **Confidence**: 10/10
- **Status**: CONFIRMED

---

### Issue ID: CEN-P3-002
- **Priority**: P3 (Minor)
- **Component**: Branding / Code Consistency
- **File**: Across backend, frontend, and tests
- **Function**: Module headers, log strings, API titles
- **Line**: Various
- **Problem**: Tri-brand naming confusion across codebase (`VulnGuard`, `Wraith`, and `CENTRIX`).
- **Expected behaviour**: Consistent project naming throughout source files, API specifications, and logs.
- **Actual behaviour**: `backend/main.py:17` sets `FastAPI(title="VulnGuard API")`; logger names in `report_generator.py` use `"wraith.report_generator"`; `test_wraith_ports.py` tests "Wraith ports"; frontend displays "CENTRIX".
- **Root cause**: Incomplete refactoring when transitioning project branding across historical iterations.
- **Impact**: Confuses developers, breaks log parsing filters, and leads to inconsistencies in exported report metadata.
- **Evidence**: `backend/main.py:17`, `backend/scanner/report_generator.py:23`, `backend/tests/test_wraith_ports.py`.
- **Reproduction**: Grep for `VulnGuard` and `Wraith` in `backend/`.
- **False positive/negative relevance**: N/A.
- **Recommended correction**: Consolidate all module titles, logs, and API metadata under the single unified name `CENTRIX`.
- **Confidence**: 10/10
- **Status**: CONFIRMED
