# CENTRIX Test Execution Log & Test Harness Forensic Audit

**Audit Mode**: Read-Only Forensic Architecture, Codebase & Runtime Audit  
**Phase**: Phase 01  
**Execution Date**: October 2026  

---

## 1. Test Environment Specification

| Component | Specification |
|---|---|
| **Operating System** | Linux (Ubuntu-based container environment, kernel 6.6.137+) |
| **System Python** | Python 3.14.7 (`/usr/bin/python3`) |
| **Virtual Environment Python** | Python 3.14.7 (`/home/sosuke/Desktop/CENTRIX-main/venv/bin/python`) |
| **Pytest Version** | Pytest 9.1.1, pluggy 1.6.0 |
| **Active Pytest Plugins** | `anyio-4.12.1`, `typeguard-4.4.4` |
| **Missing Pytest Plugins** | `pytest-asyncio` (NOT installed in system or venv) |
| **Node.js Version** | Node.js v24.19.0 (`/usr/bin/node`) |
| **Frontend Dependencies** | Missing (`FrontEnd/node_modules` does not exist) |
| **Key Missing Packages** | `chromadb` (missing from both envs), `reportlab` (installed only in venv, missing in system python) |

---

## 2. Test Execution Summary

### 2.1 Backend Test Suites (`backend/tests/` and `tests/`)

```bash
# Command executed across all test files
pytest backend/tests/test_*.py -v --tb=short
```

| Test File | Total | Passed | Failed | Exit Code | Primary Failure Root Cause |
|---|---|---|---|---|---|
| `backend/tests/test_advanced_retest.py` | 4 | 1 | 3 | 1 | `async def functions are not natively supported` (`@pytest.mark.asyncio`) |
| `backend/tests/test_agent_system.py` | 7 | 6 | 1 | 1 | `async def functions are not natively supported` (`test_tool_registry_execution`) |
| `backend/tests/test_browser_worker.py` | 2 | 1 | 1 | 1 | `async def functions are not natively supported` (`test_browser_worker_invalid_or_mock_target`) |
| `backend/tests/test_false_positive_reduction.py` | 15 | 14 | 1 | 1 | `RuntimeError: reportlab library is required` (`test_report_classification_and_confidence_columns`) |
| `backend/tests/test_live_connectors.py` | 5 | 0 | 5 | 1 | `async def functions are not natively supported` (all async tests) |
| `backend/tests/test_remediation_export.py` | 4 | 4 | 0 | 0 | Clean execution (with `datetime.utcnow()` deprecation warnings) |
| `backend/tests/test_retest_and_diff.py` | 2 | 0 | 2 | 1 | `async def functions are not natively supported` (diff and reconciliation tests) |
| `backend/tests/test_safety.py` | 4 | 4 | 0 | 0 | Clean execution |
| `backend/tests/test_safety_guardrails.py` | 6 | 5 | 1 | 1 | `async def functions are not natively supported` (`test_adaptive_rate_limiter_backoff`) |
| `backend/tests/test_secrets_isolation.py` | 4 | 4 | 0 | 0 | Clean execution (with `datetime.utcnow()` deprecation warnings) |
| `backend/tests/test_state_machine_recovery.py` | 3 | 0 | 3 | 1 | `async def functions are not natively supported` (checkpoint CRUD & resume tests) |
| `backend/tests/test_threat_intel.py` | 13 | 12 | 1 | 1 | `TypeError: object of type 'coroutine' has no len()` (`test_report_enrichment_and_warnings`) |
| `backend/tests/test_wraith_ports.py` | 17 | 16 | 1 | 1 | `RuntimeError: reportlab library is required` (`test_report_export_helpers_emit_standard_formats`) |
| `tests/test_threat_intel.py` (root) | 13 | 12 | 1 | 1 | `TypeError: object of type 'coroutine' has no len()` (`test_report_enrichment_and_warnings`) |
| **TOTALS (Unique Backend Tests)** | **99** | **79** | **20** | **1** | **79 Passed, 20 Failed** |

---

## 3. Detailed Failure Analysis & Error Traces

### Failure Category A: Missing Async Pytest Runner Plugin
- **Impacted Tests**: 17 tests across 7 files (`test_advanced_retest.py`, `test_agent_system.py`, `test_browser_worker.py`, `test_live_connectors.py`, `test_retest_and_diff.py`, `test_state_machine_recovery.py`, `test_safety_guardrails.py`).
- **Representative Trace**:
```text
______________________ test_retest_finding_xss_reproduced ______________________
async def functions are not natively supported.
You need to install a suitable plugin for your async framework, for example:
  - anyio
  - pytest-asyncio
  - pytest-tornasync
  - pytest-trio
  - pytest-twisted
=============================== warnings summary ===============================
tests/test_advanced_retest.py:84: PytestUnknownMarkWarning: Unknown pytest.mark.asyncio - is this a typo?
```
- **Forensic Diagnosis**: The codebase authored tests with `@pytest.mark.asyncio`, but neither configured `pytest-asyncio` as a dev dependency nor included an `asyncio_mode = auto` configuration in `pytest.ini` / `pyproject.toml`.

---

### Failure Category B: Unawaited Coroutine in Threat Intelligence
- **Impacted Tests**: `backend/tests/test_threat_intel.py:285` and `tests/test_threat_intel.py:285` (`test_report_enrichment_and_warnings`).
- **Exact Trace**:
```text
_____________ TestThreatIntel.test_report_enrichment_and_warnings ______________
    findings = [{"type": "sqli", "url": "http://target.com", "param": "id"}]
    enriched = enrich_findings_with_ai(findings, rag_engine=mock_engine)

>   self.assertEqual(len(enriched), 1)
E   TypeError: object of type 'coroutine' has no len()
backend/tests/test_threat_intel.py:285: TypeError
RuntimeWarning: coroutine 'enrich_findings_with_ai' was never awaited
```
- **Forensic Diagnosis**: `enrich_findings_with_ai` in `scanner/report_generator.py:30` is an `async def` function. The test caller invoked it synchronously (`enriched = enrich_findings_with_ai(...)`) without `await` or `asyncio.run()`, resulting in a runtime `TypeError`.

---

### Failure Category C: Missing ReportLab in Active Python Environment
- **Impacted Tests**: `backend/tests/test_false_positive_reduction.py::test_report_classification_and_confidence_columns` and `backend/tests/test_wraith_ports.py::WraithPortTests::test_report_export_helpers_emit_standard_formats`.
- **Exact Trace**:
```text
_______ WraithPortTests.test_report_export_helpers_emit_standard_formats _______
    def build_centrix_pdf_report(...) -> bytes:
        if not HAS_REPORTLAB:
>           raise RuntimeError("reportlab library is required to generate PDF reports. Install it with: pip install reportlab")
E           RuntimeError: reportlab library is required to generate PDF reports. Install it with: pip install reportlab
backend/reporting/pdf_report.py:57: RuntimeError
```
- **Forensic Diagnosis**: `reportlab` was installed in the repository's local `venv` directory, but the default system Python runner executing pytest lacks `reportlab`. `pdf_report.py` raises a hard `RuntimeError` rather than gracefully degrading.

---

### Failure Category D: Playwright Node CLI Driver Missing at Runtime
- **Impacted Tests**: Dynamic exploration in `test_browser_worker.py` and live scan crawling.
- **Exact Trace**:
```text
Error: Cannot find module '/usr/share/nodejs/playwright/cli.js'
    at Module._resolveFilename (node:internal/modules/cjs/loader:1517:15)
Node.js v24.19.0
Exception: Connection.init: Connection closed while reading from the driver
```
- **Forensic Diagnosis**: The Python `playwright` package was installed, but the necessary Node.js driver script `/usr/share/nodejs/playwright/cli.js` was absent from the system path, causing Chromium browser automation to abort immediately on startup.

---

## 4. Frontend Test Execution Status

- **Location**: `FrontEnd/src/__tests__/` (`client.test.ts`, `posture.test.ts`, `telemetry.test.ts`).
- **Command**: `npm test` / `vitest run`
- **Result**: **UNEXECUTABLE**.
- **Root Cause**: `FrontEnd/node_modules/` is not present in the workspace. Vitest, React Testing Library, and dependencies are uninstalled.
- **Audit Rule Adherence**: In accordance with the non-modification mandate, no `npm install` was performed during this audit.

---

## 5. Test Suite Quality & Coverage Gaps

1. **Missing Positive/Negative Detector Tests**:
   - The test suite contains zero unit tests for `_test_xss`, `_test_traversal`, `_test_open_redirect`, `_test_ssti`, or `_test_command_injection`.
   - The quad-defined `_form_probes` function in `probe.py` has zero direct unit tests asserting which definition is executed or verifying form parameter mutation.
2. **Missing Safety Boundary Tests**:
   - There are zero tests verifying DNS rebinding protection or verifying that `aiohttp` connections cannot be coerced into reaching `169.254.169.254` via 302 redirects.
3. **Missing Integration Tests**:
   - No end-to-end integration test exists that executes a complete simulated scan from `POST /api/scan/start` through all 6 stages to report generation.
