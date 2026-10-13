# CENTRIX Forensic Audit Summary

**Audit Mode**: Read-Only Forensic Architecture, Codebase & Runtime Audit  
**Phase**: Phase 01  
**Audit Completion Date**: October 2026  
**Auditor**: Antigravity Forensic Security Team  
**Status**: INVESTIGATION COMPLETE — AWAITING INDEPENDENT REVIEW  

---

## 1. High-Level Metric Register

| Audit Metric | Quantified Count |
|---|---|
| **Total Confirmed Issues** | **17** |
| **Total Likely Issues** | **3** |
| **Total Suspected Issues** | **2** |
| **Confirmed P0 (Critical)** | **3** |
| **Confirmed P1 (Major)** | **7** |
| **Confirmed P2 (Moderate)** | **5** |
| **Confirmed P3 (Minor)** | **2** |
| **Failed Automated Backend Tests** | **20** (out of 99 collected tests) |
| **Frontend Test Execution Status** | **Unexecutable** (`node_modules` not installed) |
| **Documentation Discrepancies** | **10** major verified discrepancies |
| **Major Missing Features** | **4** (Native Desktop client, Markov fuzzer, SPA Playwright runner, ChromaDB RAG) |

---

## 2. Top 10 Critical Project Risks

1. **Unauthenticated API Control Surface (`CEN-P0-002`)**: Every REST and WebSocket endpoint on port 8000 lacks authentication, allowing local or cross-origin attackers to trigger scans against third-party targets, access findings, and modify agent tasks.
2. **DNS Rebinding SSRF Vulnerability (`CEN-P0-003`)**: Target pre-flight check in `safety.py` is disconnected from runtime `aiohttp` socket creation, allowing an attacker to coerce the scanner into reaching AWS metadata (`169.254.169.254`) and internal networks.
3. **Quadruple Definition of `_form_probes` (`CEN-P0-001`)**: `backend/scanner/stages/probe.py` defines `_form_probes` 4 separate times. The 4th definition silently overwrites previous ones, while the 3rd definition treats any payload reflection as SQL injection.
4. **Missing Production Dependencies in `requirements.txt` (`CEN-P1-001`)**: `chromadb`, `flask`, `a2wsgi`, and `pytest-asyncio` are imported in core paths but omitted from the requirements manifest, breaking fresh environments and Docker deployments.
5. **Headless Browser Worker Runtime Failure (`CEN-P1-004`)**: Dynamic SPA crawling fails on startup due to missing `/usr/share/nodejs/playwright/cli.js`, causing the scanner to silently miss dynamic client-side routes and AJAX forms.
6. **Malformed Probe URL Query Construction (`CEN-P1-005`)**: Naive string concatenation `f"{url}?{param}={payload}"` generates invalid URLs with double question marks on parameterized endpoints, causing 100% false negatives.
7. **Probe / Model Invariant Desynchronization (`CEN-P1-006`)**: Active probes assert `"Confirmed"` status without creating `EvidenceArtifact` records; the Pydantic model validator immediately demotes all findings to `"Tentative"`.
8. **Plaintext Secret & Token Storage (`CEN-P2-001` / Security Audit)**: Jira tokens, GitHub access tokens, and API credentials are saved unencrypted in `centrix.db`.
9. **SQLi False Positives via Length-Based Differential (`CEN-P2-005`)**: Dynamic content (timestamps, CSRF tokens, rotating banners) triggering >125-character length shifts causes the scanner to falsely report confirmed boolean SQL injection.
10. **Synchronous Blocking SQLite I/O in Async Coroutines (`CEN-P2-001`)**: Synchronous `sqlite3.connect` and execution calls inside `async def` functions block the Python event loop under concurrent load.

---

## 3. Recommended Remediation Order

Remediation should proceed strictly according to the 12-phase specification in `CENTRIX_IMPLEMENTATION_ROADMAP.md`:

```text
Phase 1: Baseline and Architecture Corrections (Fix probe shadowing, URL builder, branding)
   ↓
Phase 2: Runtime and Build Reliability (Fix requirements.txt, pytest harness, async tests)
   ↓
Phase 3: Scanner-Core Correctness (HTTP method support, JSON bodies, timeout handling)
   ↓
Phase 4: False-Positive Reduction (Context-aware XSS, DOM-normalized SQLi, header rules)
   ↓
Phase 5: False-Negative Reduction (Playwright SPA repair, blind SQLi, LFI variants)
   ↓
Phase 6: Evidence, Confidence, CWE/CVSS & Deduplication (Persist wire bytes to artifacts)
   ↓
Phase 7: AI / RAG Verification (ChromaDB stabilization, remove fabricated Markov claims)
   ↓
Phase 8: Reporting and Database Reliability (aiosqlite migration, PDF export safeguards)
   ↓
Phase 9: Security Hardening (DNS rebinding transport pinning, API token auth, secret encryption)
   ↓
Phase 10: Performance, Concurrency & Rate Limiting (Adaptive backoff on 429/503)
   ↓
Phase 11: End-to-End Regression Testing (Validation against benchmark applications)
   ↓
Phase 12: Final Release Validation (Docker compose verification, clean packaging)
```

---

## 4. Audit Report Locations

All generated Phase 01 forensic audit reports have been compiled in the repository at:

- `audit_reports/phase_01/CENTRIX_MASTER_AUDIT.md`
- `audit_reports/phase_01/CENTRIX_ISSUE_REGISTER.md`
- `audit_reports/phase_01/CENTRIX_DETECTION_ACCURACY.md`
- `audit_reports/phase_01/CENTRIX_TEST_EXECUTION.md`
- `audit_reports/phase_01/CENTRIX_DOCUMENTATION_VS_CODE.md`
- `audit_reports/phase_01/CENTRIX_SECURITY_AUDIT.md`
- `audit_reports/phase_01/CENTRIX_IMPLEMENTATION_ROADMAP.md`
- `audit_reports/phase_01/CENTRIX_AUDIT_SUMMARY.md`
