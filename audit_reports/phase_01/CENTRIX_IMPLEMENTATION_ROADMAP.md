# CENTRIX Phased Remediation Roadmap & Acceptance Criteria

**Audit Mode**: Read-Only Forensic Architecture, Codebase & Runtime Audit  
**Phase**: Phase 01  
**Status**: PLANNING & REMEDIATION SPECIFICATION (Execution deferred until audit sign-off)  

---

## 1. Overview & Remediation Strategy

The remediation of CENTRIX is organized into 12 sequential, logically bounded phases designed to eliminate technical debt, restore build and runtime reliability, fix critical detector flaws, eliminate false positives, and harden the security of the application itself.

Remediation must proceed strictly in this order; no higher-level AI or scanner feature can be trusted until the baseline environment, probe core, and evidence pipeline are verified.

---

## 2. Remediation Phases

### Phase 1: Baseline & Architectural Corrections
- **Objective**: Clean up codebase pollution, eliminate duplicate function definitions, resolve branding discrepancies, and remove dead code.
- **Key Tasks**:
  1. Remove the 3 shadowed duplicate definitions of `_form_probes` in `backend/scanner/stages/probe.py` (lines 343, 404, 861) and consolidate on a single clean implementation.
  2. Remove dead code `_test_sqli` (lines 156-207 in `probe.py`).
  3. Standardize application branding across backend titles, logs, and frontend strings to `CENTRIX` (eliminating `VulnGuard` and `Wraith` drift).
  4. Fix URL string interpolation bug in `probe.py` (replace naive `f"{url}?{param}={payload}"` with `urllib.parse` query builders).
- **Acceptance Criteria**:
  - `probe.py` contains exactly one definition of `_form_probes`.
  - Zero dead functions in `probe.py`.
  - All logs and API titles report `CENTRIX`.
  - Parameterized URLs with existing queries format correctly without double `?` syntax.

---

### Phase 2: Runtime & Build Reliability
- **Objective**: Fix missing dependencies, resolve broken test runners, and stabilize environment builds.
- **Key Tasks**:
  1. Update `backend/requirements.txt` to include `chromadb`, `flask`, `a2wsgi`, `pytest-asyncio`, and `reportlab`.
  2. Configure `pytest.ini` with `asyncio_mode = auto` so all `@pytest.mark.asyncio` tests execute out-of-the-box.
  3. Fix synchronous unawaited call to `enrich_findings_with_ai` in `backend/tests/test_threat_intel.py:285`.
  4. Fix Playwright installation and container environment scripts so Chromium and Node CLI drivers run reliably.
- **Acceptance Criteria**:
  - `pip install -r backend/requirements.txt` installs a complete, functional backend environment.
  - `pytest backend/tests/` executes all 99 backend tests with 100% pass rate.
  - Zero `DeprecationWarning` for `datetime.utcnow()`.

---

### Phase 3: Scanner-Core Correctness
- **Objective**: Ensure all active probe modules correctly test targets, generate well-formed requests, and parse responses accurately.
- **Key Tasks**:
  1. Ensure all URL and form payloads are properly URL-encoded / body-encoded before transmission.
  2. Implement proper HTTP method handling (support JSON POST/PUT payloads in active probes).
  3. Fix form field discovery to respect CSRF tokens and required fields during submission.
  4. Ensure probe timeout and cancellation handlers cleanly abort inflight connections when scans are stopped.
- **Acceptance Criteria**:
  - Probe modules successfully submit both GET query parameters and POST form/JSON payloads.
  - Scans honor the user-configured timeout and concurrency limits.
  - Stop/pause commands cleanly terminate active aiohttp sessions.

---

### Phase 4: False-Positive Reduction
- **Objective**: Eliminate confirmed and likely false-positive triggers across vulnerability detectors.
- **Key Tasks**:
  1. **XSS**: Require response `Content-Type` validation (reject `application/json`), context check (check whether reflection is inside quotes or executable tags), and entity encoding check (`&lt;script&gt;`).
  2. **SQLi**: Replace brittle length-differential modulo check with dynamic content normalization (strip tokens, timestamps, and numbers before comparing true/false responses).
  3. **Security Headers**: Ensure missing headers are never elevated to high/critical vulnerabilities and are properly flagged as informational observations.
- **Acceptance Criteria**:
  - JSON API endpoints reflecting query strings do not trigger Reflected XSS.
  - Pages with dynamic timestamps or rotating banners do not trigger False-Positive Boolean SQLi.
  - Security headers are categorized as `informational` with zero CVSS inflation.

---

### Phase 5: False-Negative Reduction
- **Objective**: Expand detector coverage to catch legitimate vulnerabilities currently missed.
- **Key Tasks**:
  1. Enable Playwright dynamic SPA exploration to extract routes and forms from client-rendered JavaScript applications.
  2. Expand XSS payload portfolio to include attribute breakouts, event handlers, and script-tag breakouts.
  3. Add time-based blind SQL injection verification (`sleep(5)`) with baseline timing checks.
  4. Add LFI/path traversal payload variants (URL-encoded `..%2f`, null bytes, Windows `win.ini` variants).
- **Acceptance Criteria**:
  - Scanner discovers and tests dynamic routes on test Single Page Applications.
  - Blind SQL injection is detected and confirmed via reproducible timing deltas.
  - Path traversal is detected across both Unix and Windows target architectures.

---

### Phase 6: Evidence, Confidence, CWE/CVSS & Deduplication
- **Objective**: Synchronize probe output with finding validation invariants and ensure enterprise-grade reporting metadata.
- **Key Tasks**:
  1. Update `probe.py` so every positive detection persists raw request and response wire bytes into `EvidenceArtifact` in `store.add_evidence()`.
  2. Link `evidence_artifact_ids` to generated findings so the `Finding` model validator does not downgrade valid findings to `Tentative`.
  3. Review and correct all CWE and CVSS base score mappings across all vulnerability categories.
  4. Implement robust finding deduplication hashing across normalized URLs and parameter sinks.
- **Acceptance Criteria**:
  - Every confirmed finding in the database has an accessible, linked `EvidenceArtifact`.
  - Model validator preserves `Confirmed` status for findings with verified evidence.
  - Zero duplicate findings generated for the same endpoint parameter sink.

---

### Phase 7: AI / Threat Intel / RAG Verification
- **Objective**: Stabilize RAG threat intelligence enrichment, remove fabricated claims, and ensure robust offline/online fallbacks.
- **Key Tasks**:
  1. Verify ChromaDB vector store initialization and provide automated SQLite/file fallback when vector database is unavailable.
  2. Revise whitepapers and documentation to remove all fabricated claims regarding Markov-chain fuzzers and unverified 98.4% precision metrics.
  3. Ensure RAG enrichment is strictly additive (never alters deterministic evidence or severity).
  4. Enforce strict anti-hallucination guardrails: suppress or flag any CVE citations not present in retrieved context.
- **Acceptance Criteria**:
  - Threat intel pipeline runs reliably with or without local Ollama daemon.
  - Anti-hallucination warning banner appears whenever an ungrounded CVE is referenced.
  - All whitepapers accurately reflect the true engineering architecture.

---

### Phase 8: Reporting & Database Reliability
- **Objective**: Replace database anti-patterns and ensure resilient multi-format reporting.
- **Key Tasks**:
  1. Migrate `backend/db/store.py` to `aiosqlite` or wrap blocking SQLite calls in `asyncio.to_thread`.
  2. Implement schema migration from single-column JSON payloads to structured columns for high-query fields (scan status, severity counts).
  3. Fix `backend/reporting/pdf_report.py` to gracefully fall back to HTML report generation if `reportlab` is unavailable.
  4. Validate SARIF and JUnit outputs against official schema validators.
- **Acceptance Criteria**:
  - Database operations do not block the asyncio event loop under 100 concurrent requests.
  - PDF/HTML reports download cleanly without HTTP 500 crashes.
  - Exported SARIF reports import successfully into GitHub Advanced Security.

---

### Phase 9: Security Hardening of CENTRIX Itself
- **Objective**: Remediate critical security vulnerabilities within the scanner application.
- **Key Tasks**:
  1. **SSRF**: Implement IP-pinned HTTP transport (`aiohttp.TCPConnector`) to defeat DNS rebinding TOCTOU attacks; validate redirect destinations before following.
  2. **API Auth**: Implement token-based authentication (`Authorization: Bearer <token>`) for all REST API and WebSocket routes.
  3. **Secret Encryption**: Encrypt all third-party integration secrets (Jira, GitHub, API keys) stored in `centrix.db` using AES-256-GCM.
  4. **Output Sanitization**: Ensure all target data rendered into PDF, HTML, or UI components is strictly entity-escaped.
- **Acceptance Criteria**:
  - DNS rebinding test domains cannot force connections to `127.0.0.1` or `169.254.169.254`.
  - All API routes return HTTP 401 when requested without valid authentication.
  - Secrets in `centrix.db` cannot be read without the encryption key.

---

### Phase 10: Performance, Concurrency & Rate Limiting
- **Objective**: Optimize scan throughput while ensuring graceful rate limiting and resource governance.
- **Key Tasks**:
  1. Implement adaptive rate limiting with automatic backoff on HTTP 429 / 503 responses.
  2. Optimize memory footprint during large crawls by streaming responses and capping max URLs discovered.
  3. Implement worker task queues for background scan execution.
- **Acceptance Criteria**:
  - Scanner smoothly throttles requests when target responds with HTTP 429 Too Many Requests.
  - Memory consumption remains stable (<500MB) during 5,000-request scan runs.

---

### Phase 11: End-to-End Regression Testing
- **Objective**: Validate the remediated system against controlled, intentionally vulnerable benchmark applications.
- **Key Tasks**:
  1. Test scanner against local OWASP Juice Shop or DVWA container targets.
  2. Assert true positive detection of seeded vulnerabilities (SQLi, XSS, Traversal, SSRF).
  3. Assert zero false positive findings on clean baseline static endpoints.
  4. Verify checkpoint pause and resume recovery mid-scan.
- **Acceptance Criteria**:
  - Verified detection of all seeded vulnerabilities.
  - 100% test pass rate across end-to-end integration test harness.

---

### Phase 12: Final Release & Packaging Validation
- **Objective**: Prepare verified release artifacts, documentation, and client distribution.
- **Key Tasks**:
  1. Verify Docker Compose deployment (`docker compose up --build`) initializes database and frontend cleanly.
  2. Either implement a true native desktop wrapper (Tauri) or update desktop documentation to accurately label `centrix_desktop.py` as a developer CLI launcher.
  3. Generate finalized, verified user and API documentation.
- **Acceptance Criteria**:
  - Docker Compose boots to a fully operational frontend and backend in one command.
  - Documentation accurately reflects tested capabilities.
  - Project owner signs off on remediation completion.
