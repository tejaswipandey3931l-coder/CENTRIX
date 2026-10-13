# CENTRIX Documentation vs. Code Forensic Discrepancy Audit

**Audit Mode**: Read-Only Forensic Architecture, Codebase & Runtime Audit  
**Phase**: Phase 01  
**Scope**: Comparison of README, Architecture Whitepapers (`CENTRIX_How_ML_Works.pdf`, `CENTRIX_ML_Integration_Architecture.pdf`), and docstrings against actual code and runtime execution.

---

## 1. Discrepancy Matrix

| Claimed Feature | Source Documentation | Code Implementation | Runtime Evidence | Forensic Status |
|---|---|---|---|---|
| **Offensive Markov-Chain Fuzzing Engine** | `CENTRIX_How_ML_Works.pdf` & `generate_ml_explainer_pdf.py:124, 138, 228`: "Markov-chain payload generators... train on known exploit syntax to generate obfuscated payloads" | **Zero implementation**. No Markov chain classes, state transition matrices, or training routines exist in any file. | Grep for `markov` returns only the whitepaper generator script itself. | **NOT IMPLEMENTED / FABRICATED** |
| **98.4% Report Accuracy Score** | `generate_ml_explainer_pdf.py:282`: "Report Accuracy Score: 98.4% grounded precision with automated hallucination warning banners" | Hardcoded string in PDF generator; no precision evaluation dataset, benchmark runner, or ground truth corpus exists. | String search verifies `98.4` appears only as hardcoded text in the PDF builder. | **NOT IMPLEMENTED / FABRICATED** |
| **100% On-Premise Air-Gapped ML Guarantee** | `CENTRIX_How_ML_Works.pdf:281`: "Air-Gap & Privacy Score: 100% On-Premise. Zero outbound internet calls required for ML inference." | `.env.example`, `docker-compose.yml`, and `agent/debate.py:102, 140` hardcode external cloud API `https://api.xkiro.com/v1` and models (`minimax/minimax-m3:free`). | Outbound HTTP requests to `api.xkiro.com` are dispatched when `XKIRO_API_KEY` is set. | **DOCUMENTATION ERROR / CONTRADICTION** |
| **Persistent ChromaDB Vector Store** | Whitepapers & `backend/scanner/threat_intel/vector_store.py`: "Vector Database (ChromaDB) stores and indexes vector embeddings locally for sub-100ms cosine similarity search" | Code wrapper exists in `vector_store.py`, but `chromadb` is omitted from `requirements.txt` and not installed in the environment. | RAG engine crashes or is caught by fallback: `[WARN] Could not initialize RagEngine: No module named 'chromadb'`. | **PARTIALLY VERIFIED / BROKEN AT RUNTIME** |
| **Dynamic SPA Crawling via Playwright** | README & `backend/scanner/engine.py:260-278`: "Launching Headless Chromium Worker for dynamic SPA discovery..." | `backend/scanner/browser/worker.py` contains async Playwright calls. | Runtime execution aborts with `Cannot find module '/usr/share/nodejs/playwright/cli.js'`; crawler catches exception and skips. | **PARTIALLY VERIFIED / BROKEN AT RUNTIME** |
| **Multi-Agent Debate Adjudication** | README & whitepapers: "Autonomous multi-agent debate adjudicates every finding to eliminate false positives" | `backend/agent/debate.py` contains a dual-specialist + adjudicator prompt flow; capped at top 15 candidates; falls back to hardcoded offline rules when API key is missing. | In offline mode, executes purely deterministic `_fallback_adjudication` without any neural model invocation. | **PARTIALLY VERIFIED** |
| **Native Desktop Application (.exe / .dmg)** | `desktop/centrix_desktop.py:3-5`: "Packaging-friendly bridge toward a future Tauri/Electron .exe" | Merely a 70-line Python script executing `subprocess.Popen` for `uvicorn` and `npm run dev` and calling `webbrowser.open()`. | No Tauri, Electron, PySide, or compiled desktop binary exists. | **NOT IMPLEMENTED / PLACEHOLDER** |
| **Strict Scope Enforcement & SSRF Safety** | `backend/scanner/safety.py`: "Rejects loopback, RFC1918, link-local and reserved IPs" | `ensure_public_target` performs a single hostname resolution at startup. | Vulnerable to DNS rebinding TOCTOU because `aiohttp` subsequent socket connections re-resolve DNS without IP pinning. | **DEFECTIVE IMPLEMENTATION** |
| **Verified DAST Evidence Classification** | `backend/api/models.py`: Confirmed findings require verified persisted evidence artifacts | `backend/scanner/stages/probe.py` asserts `"Confirmed"` on raw text reflection without creating `EvidenceArtifact` records. | Pydantic model validator downgrades all probe-confirmed findings to `"Tentative"` with warning reasons. | **DEFECTIVE IMPLEMENTATION** |
| **Unified Application Branding** | Frontend and Whitepapers: "CENTRIX Security Framework" | Codebase mixes `VulnGuard` (FastAPI title, engine logs), `Wraith` (logger namespaces, port tests), and `CENTRIX`. | `backend/main.py:17` displays `VulnGuard API v4.0.0`; `probe.py:165` logs `VulnGuard Engine`. | **DOCUMENTATION ERROR / CODE DRIFT** |

---

## 2. In-Depth Analysis of Major Discrepancies

### 2.1 The Markov Chain & Statistical ML Claims
The PDF whitepaper generator `generate_ml_explainer_pdf.py` asserts:
> *"Offensive ML: Exploitation Payloads & Attack Chains... Markov-Chain Fuzzing Models: Offensive ML models train on known exploit syntax to generate obfuscated payloads that bypass WAF rules."*

**Forensic Reality**: An exhaustive regex and AST search of every `.py`, `.ts`, and `.js` file across the repository reveals **zero** Markov chain code. The payloads used during probing (`probe.py`) are hardcoded static string arrays (`['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>']` and `["'", "' OR '1'='1", "1 AND 1=1"]`). The Markov chain claim is pure fabrication.

---

### 2.2 The 98.4% Precision Metric
The whitepaper claims an empirical benchmark score of **98.4% grounded precision**.
- There is no test dataset (e.g. OWASP Benchmark, WAVSEP, or custom vulnerable app suite) in the repository.
- There is no script that runs precision/recall calculations.
- The number `98.4%` exists exclusively as a hardcoded string inside `generate_ml_explainer_pdf.py:282`.

---

### 2.3 The "100% Air-Gapped On-Premise" Contradiction
While the whitepaper promises a 100% air-gapped system where zero data leaves the local machine, the actual configuration files (`.env.example`, `docker-compose.yml`, `backend/agent/config.py`) are pre-configured to communicate with an external cloud service (`https://api.xkiro.com/v1`) using third-party hosted models (`minimax/minimax-m3:free`). When this key is provided, vulnerability snippets and target URLs are transmitted over the internet to external API endpoints.

---

### 2.4 Desktop App Misrepresentation
The repository has a top-level directory `/desktop/` containing `centrix_desktop.py`.
The file docstring claims:
```python
"""Centrix Desktop Agent scaffold.
This launcher starts the local backend and opens the web console. It is a
packaging-friendly bridge toward a future Tauri/Electron `.exe`.
"""
```
However, outside of opening a browser window to `http://127.0.0.1:8443/`, no desktop client exists. If Node.js or `FrontEnd/node_modules` is absent on the host machine, the desktop launcher fails silently.
