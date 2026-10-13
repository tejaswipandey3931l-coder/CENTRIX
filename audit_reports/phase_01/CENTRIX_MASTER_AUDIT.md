# CENTRIX Master Forensic Audit Report

**Audit Mode**: Read-Only Forensic Architecture, Codebase & Runtime Audit  
**Target Repository**: `/home/sosuke/Desktop/CENTRIX-main`  
**Audit Phase**: Phase 01  
**Audit Date**: October 2026  
**Auditor**: Antigravity Forensic Security Team  
**Status**: COMPLETE (Investigation Only — Zero Code Modifications Applied)  

---

## 1. Executive Summary

CENTRIX (internally referencing legacy names *VulnGuard* and *Wraith*) is conceived as a multi-stage Dynamic Application Security Testing (DAST) web platform with an AI-assisted threat intelligence enrichment pipeline, false-positive reduction subsystem, and an interactive cybersecurity analyst UI.

This forensic audit inspected the entire repository—including the FastAPI backend, React/Vite frontend, desktop launcher wrapper, DAST pipeline stages, vulnerability detectors, threat intelligence engine, multi-agent debate components, database architecture, test suites, and project whitepapers.

The codebase presents a sharp dichotomy:
1. **The Core DAST Pipeline and Architectural Vision**: Sophisticated multi-stage scanning architecture with explicit safety boundaries, structured state machine checkpoints, and an evidence scoring matrix.
2. **Execution & Implementation Reality**: Critical defects, broken test harnesses, architectural fragmentation, missing external dependencies (`chromadb`, `playwright` driver, `pytest-asyncio`), multiple shadowed duplicate function definitions, and significant marketing-versus-implementation discrepancies (e.g., Markov-chain fuzzers and 98.4% precision metrics fabricated in whitepaper generators but nonexistent in the codebase).

---

## 2. Project Purpose & Original Idea

### 2.1 The Problem CENTRIX Was Intended to Solve
Traditional web vulnerability scanners (e.g., legacy DAST tools) suffer from high false-positive rates, poor coverage of modern Single Page Applications (SPAs), disconnected workflows between crawling and manual testing, and generic remediation advice. CENTRIX was designed to solve this by:
- Merging automated DAST probing with manual security testing utilities (Proxy history, Repeater, Intruder, Decoder, Comparer).
- Incorporating an intelligent false-positive reduction layer combining deterministic response diffing with an AI adjudicator.
- Enriching discovered vulnerabilities with real-time threat intelligence (NVD, GitHub Advisories, CISA-KEV, Exploit-DB) via local semantic retrieval (RAG).

### 2.2 Intended User
- Application Security (AppSec) Engineers and Penetration Testers requiring an integrated workbench.
- Security Operations (SecOps) teams seeking automated vulnerability verification and ticket export (Jira, GitHub Issues).
- Developers needing reproducible `curl` reproduction commands and contextual fix guidance.

### 2.3 What Makes CENTRIX Different from Basic Scanners
Unlike simple single-threaded request fuzzers:
- **State Machine Checkpointing**: Allows long scans to pause, resume, and recover from failures without losing crawl state.
- **Evidence-Based Finding Verification**: Distinguishes tentative candidates from confirmed findings using strict evidence scoring invariants and persisted request/response artifacts.
- **Hybrid Manual/Automated Interface**: Incorporates Burp Suite-like manual tools directly into the web UI.

---

## 3. Actual Architecture vs. Documented Architecture

### 3.1 Documented / Claimed Flow
```text
User 
  → Desktop Launcher (Tauri/Electron .exe)
  → Vite Web Console (Three.js 3D Risk Matrix)
  → FastAPI Engine (v4.0.0)
  → Multi-Agent Orchestrator
  → Playwright Headless SPA Crawler
  → Active & Passive Probing Modules
  → Local Air-Gapped RAG Engine (Ollama qwen2.5-coder + ChromaDB + Markov Chains)
  → Multi-Agent Adjudication Debate (Dual Specialist + Judge)
  → Evidence Store & SQLite DB
  → Multi-Format Report Exporter (PDF, SARIF, JUnit)
```

### 3.2 Actual Implemented Execution Flow
```text
User / Browser
  │
  ▼
Frontend (React 19 / Vite / TailwindCSS v4)
  │  [Unauthenticated REST / WebSocket calls to localhost:8000]
  ▼
FastAPI Backend (backend/main.py)
  │  ├── Mounted Routers (scan, findings, reports, evidence, etc.)
  │  └── Mounted Flask Threat Intel Blueprint (via WSGIMiddleware)
  ▼
Target Validation (backend/scanner/stages/validate.py & scanner/safety.py)
  │  ├── ensure_public_target(): DNS resolve & RFC1918 block (Vulnerable to DNS Rebinding TOCTOU)
  │  └── Robots.txt parse & HTTP normalization
  ▼
Discovery (backend/scanner/stages/discover.py)
  │  └── Brute-force directory wordlist (404 baseline diffing) & common port probe
  ▼
Crawler (backend/scanner/stages/crawl.py)
  │  ├── aiohttp HTMLParser regex link & form extraction
  │  └── Headless Browser (scanner/browser/worker.py): Playwright (Fails at runtime: missing Node CLI driver)
  ▼
Probe Engine (backend/scanner/stages/probe.py + wraith_advanced.py + passive.py)
  │  ├── Form Probes: SHADOWED 4 TIMES in probe.py (Last definition at line 898 overrides lines 343, 404, 861)
  │  ├── SQLi Probe: _test_sqli_v2 active; _test_sqli dead code
  │  ├── XSS Probe: String reflection check only (ignores Content-Type, script context, HTML encoding)
  │  └── Path Traversal Probe: Signature check ("root:x:0:0")
  ▼
Finding Analysis & FP Reduction (backend/scanner/stages/analyze.py)
  │  ├── Deterministic Evidence Scorer (scanner/validation/scorer.py)
  │  ├── AI Adjudication Debate (backend/agent/debate.py):
  │  │     └── If XKIRO_API_KEY missing -> falls back to deterministic rule engine
  │  └── Finding Invariant Validation (api/models.py): Downgrades "Confirmed" -> "Tentative" if no EvidenceArtifact
  ▼
AI Threat Intel RAG Enrichment (backend/scanner/report_generator.py)
  │  └── Imports scanner/threat_intel/rag_engine.py -> Fails silently (chromadb not installed)
  ▼
Persistence & Reporting
     ├── SQLite Database (backend/db/store.py): Single-table JSON payload store (blocks event loop)
     └── Report Generator:
           ├── SARIF / JUnit: Functional
           └── PDF Report: Fails if reportlab not installed in active environment
```

---

## 4. Implementation Status Breakdown

| Category | Components / Modules | Status / Reality |
|---|---|---|
| **IMPLEMENTED AND WORKING** | Scan state machine, checkpoint save/restore, scope enforcement (`url_in_scope`), SARIF exporter, JUnit exporter, Jira/GitHub export builders, CORS configuration, SQLite store operations (basic CRUD), manual testing utility routers (decoder, comparer). | Fully functional in isolated unit execution. |
| **IMPLEMENTED BUT DEFECTIVE** | `scanner/stages/probe.py` (quadruple definition of `_form_probes`, unencoded URL parameters, double `?` syntax error on parameterized URLs); `scanner/safety.py` (DNS rebinding vulnerability); `reporting/pdf_report.py` (hard crash when reportlab is absent); `scanner/report_generator.py` (`enrich_findings_with_ai` defined async but invoked synchronously in tests). | Code exists but contains critical runtime errors or logic bugs. |
| **PARTIALLY IMPLEMENTED** | `scanner/threat_intel/rag_engine.py` (implements RAG pipeline logic, but cannot run because `chromadb` is missing and untracked in `requirements.txt`); `scanner/browser/worker.py` (Playwright code exists, but fails with missing Node CLI driver); `desktop/centrix_desktop.py` (not a Tauri/Electron build, merely a 70-line Python subprocess wrapper). | Scaffolding exists, cannot execute end-to-end without external fixes. |
| **DOCUMENTATED BUT NOT IMPLEMENTED** | Markov-chain offensive fuzzing engine; 98.4% grounded precision validation engine; autonomous multi-agent planner in live scan loop; 100% air-gapped local model guarantee (code hardcodes external `api.xkiro.com`). | Fabricated in documentation/PDF whitepapers with zero code backing. |
| **DEAD OR UNUSED CODE** | `scanner/stages/probe.py`: `_test_sqli` (lines 156-207, never called by `probe.run`); `_form_probes` definitions at lines 343, 404, and 861; `backend/agent/orchestrator.py` (never invoked by scanner engine; only exposed via standalone `/api/agent/*` endpoints). | Code exists in repo, never reachable in production scan path. |
| **UNKNOWN / REQUIRES FURTHER TESTING** | Live Jira/GitHub enterprise webhook dispatch; OOB DNS listener under multi-threaded callback floods. | Requires external mock infrastructure. |

---

## 5. Architectural & Security Weaknesses

1. **Unauthenticated Backend API Surface**:
   - Every single endpoint under `/api/*` (including scan control, secret management, file imports, and remote command tasks) lacks authentication or token authorization.
2. **Database Anti-Pattern**:
   - `backend/db/store.py` stores all entities across 14 tables as raw JSON strings (`(id TEXT PRIMARY KEY, payload TEXT NOT NULL)`).
   - All SQLite queries are executed synchronously directly inside async coroutines (`def get_scan()`, `def list_scans()`), stalling the Python asyncio event loop during database I/O.
3. **SSRF via DNS Rebinding**:
   - `ensure_public_target` performs a single hostname resolution at scan startup. `aiohttp` subsequent connections re-resolve DNS dynamically without IP pinning, exposing localhost and AWS cloud metadata (`169.254.169.254`) to rebinding attacks.
4. **Dependency Fragmentation**:
   - Critical dependencies (`chromadb`, `flask`, `a2wsgi`, `pytest-asyncio`) are imported in core paths but completely omitted from `backend/requirements.txt`.
5. **Probe Logic Desynchronization**:
   - `probe.py` asserts findings as `"Confirmed"` based on raw substring reflection, but does not construct or attach `EvidenceArtifact` IDs. The `Finding` model validator immediately demotes them to `"Tentative"` due to missing artifacts.

---

## 6. Overall Forensic Assessment

CENTRIX has substantial foundation work in its UI design, state tracking, and DAST pipeline concepts. However, it currently suffers from severe codebase drift: duplicate code blocks pasted across files, phantom dependencies, unhandled async coroutines, and marketing claims of AI capabilities that do not exist.

Before CENTRIX can be deployed or relied upon as a trusted security testing tool, it requires a structured, multi-phase stabilization addressing architecture, runtime environments, detector correctness, and security hardening.
