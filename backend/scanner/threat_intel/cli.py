#!/usr/bin/env python3
"""
wraith-intel CLI
-----------------
Command-line interface for the Wraith Threat Intelligence RAG pipeline.

Usage
-----
  python -m scanner.threat_intel.cli --help

  # Analyse a Python file
  wraith-intel analyse code path/to/app.py --language python

  # Analyse a requirements.txt
  wraith-intel analyse manifest requirements.txt

  # Analyse specific CVEs
  wraith-intel analyse cve CVE-2024-1234 CVE-2023-5678

  # Natural language security query
  wraith-intel query "What vulnerabilities affect Apache Log4j?"

  # Trigger a sync
  wraith-intel sync --nvd-days 30

  # Check status
  wraith-intel status
  wraith-intel health
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Optional

# ─────────────────────────────────────────────────────────────────────────────
# Colour helpers (no external deps)
# ─────────────────────────────────────────────────────────────────────────────

_COLOURS = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "red": "\033[91m",
    "yellow": "\033[93m",
    "green": "\033[92m",
    "cyan": "\033[96m",
    "magenta": "\033[95m",
    "grey": "\033[90m",
}

def _c(colour: str, text: str) -> str:
    if sys.stdout.isatty():
        return f"{_COLOURS.get(colour, '')}{text}{_COLOURS['reset']}"
    return text

def _risk_colour(risk: str) -> str:
    mapping = {
        "critical": "red",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
        "info": "grey",
        "unknown": "grey",
    }
    return mapping.get(risk.lower(), "grey")


# ─────────────────────────────────────────────────────────────────────────────
# Output formatters
# ─────────────────────────────────────────────────────────────────────────────

def _print_header(title: str) -> None:
    width = 72
    print()
    print(_c("cyan", "─" * width))
    print(_c("bold", f"  {title}"))
    print(_c("cyan", "─" * width))


def _print_result(result: Dict[str, Any], json_output: bool = False) -> None:
    if json_output:
        print(json.dumps(result, indent=2, default=str))
        return

    risk = result.get("risk_level", "unknown")
    risk_col = _risk_colour(risk)

    _print_header("Wraith Threat Intelligence — Analysis Result")
    print(f"  Type    : {_c('bold', result.get('query_type', ''))}")
    print(f"  Summary : {result.get('query_summary', '')}")
    print(f"  Risk    : {_c(risk_col, risk.upper())}")
    print(f"  Model   : {_c('grey', result.get('model_used', ''))}")

    cves = result.get("matched_cves") or []
    if cves:
        print(f"\n  {_c('bold', 'Matched CVEs:')} {_c('yellow', ', '.join(cves))}")

    advisories = result.get("retrieved_advisories") or []
    if advisories:
        print(f"\n{_c('bold', '  Retrieved Advisories:')}")
        for adv in advisories[:6]:
            kev = " 🔴 KEV" if adv.get("cisa_kev") else ""
            sev = adv.get("severity", "?")
            sev_col = _risk_colour(sev)
            print(
                f"    [{_c(sev_col, sev.upper())}] {adv.get('cve_id','')} — "
                f"{adv.get('title','')[:60]}{kev}"
                f"  (CVSS {adv.get('cvss_score', 0)}, sim {adv.get('similarity', 0):.0%})"
            )

    steps = result.get("remediation_steps") or []
    if steps:
        print(f"\n{_c('bold', '  Remediation Steps:')}")
        for i, step in enumerate(steps[:8], 1):
            print(f"    {i}. {textwrap.fill(step, width=68, subsequent_indent='       ')}")

    llm = (result.get("llm_analysis") or "").strip()
    if llm:
        print(f"\n{_c('bold', '  LLM Analysis:')}")
        for line in llm.splitlines():
            print(f"  {line}")

    if result.get("error"):
        print(f"\n  {_c('red', 'Error:')} {result['error']}")

    print()


def _print_status(status: Dict[str, Any]) -> None:
    _print_header("Wraith Threat Intel — Status")
    store = status.get("store") or {}
    print(f"  Collection : {store.get('collection', '')}")
    print(f"  DB Path    : {store.get('persist_dir', '')}")
    print(f"  Chunks     : {store.get('total_chunks', 0):,}")
    wm = store.get("watermarks") or {}
    for feed, ts in wm.items():
        print(f"  {feed:<12}: last synced {ts or 'never'}")

    sched = status.get("scheduler") or {}
    print(f"\n  Scheduler  : {'running' if sched.get('running') else 'stopped'}")
    print(f"  Interval   : every {sched.get('sync_interval_hours', '?')}h")
    for job in (sched.get("jobs") or []):
        print(f"  Job        : {job.get('name','')} → next run {job.get('next_run', 'N/A')}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# CLI commands
# ─────────────────────────────────────────────────────────────────────────────

def cmd_health(args: argparse.Namespace) -> None:
    from .ollama_client import SyncOllamaClient
    from .vector_store import ThreatIntelVectorStore
    client = SyncOllamaClient()
    ok = client.health()
    models = client.list_models() if ok else []
    store = ThreatIntelVectorStore()

    _print_header("Wraith Threat Intel — Health")
    col = "green" if ok else "red"
    print(f"  Ollama  : {_c(col, 'reachable' if ok else 'UNREACHABLE')}")
    if models:
        print(f"  Models  : {', '.join(models[:8])}")
    from .config import cfg
    print(f"  Chat    : {cfg.ollama_chat_model}")
    print(f"  Embed   : {cfg.ollama_embed_model}")
    col2 = "green" if store.count() >= 0 else "red"
    print(f"  Store   : {_c(col2, 'ok')}  ({store.count():,} chunks)")
    print()
    if not ok:
        sys.exit(1)


def cmd_status(args: argparse.Namespace) -> None:
    from .sync_worker import get_scheduler
    from .vector_store import ThreatIntelVectorStore
    store = ThreatIntelVectorStore()
    scheduler = get_scheduler()
    stats = store.stats()
    scheduler_info = {
        "running": scheduler.running,
        "jobs": [
            {
                "id": j.id,
                "name": j.name,
                "next_run": str(getattr(j, "next_run_time", None)) if getattr(j, "next_run_time", None) else None,
            }
            for j in scheduler.get_jobs()
        ],
        "sync_interval_hours": __import__("scanner.threat_intel.config", fromlist=["cfg"]).cfg.sync_interval_hours,
    }
    _print_status({"store": stats, "scheduler": scheduler_info})


def cmd_sync(args: argparse.Namespace) -> None:
    from .sync_worker import run_sync
    print(_c("cyan", f"  Starting sync  (NVD last {args.nvd_days} days, CISA-KEV, GHSA)…"))
    summary = run_sync(
        nvd_days=args.nvd_days,
        skip_nvd=args.skip_nvd,
        skip_cisa=args.skip_cisa,
        skip_ghsa=args.skip_ghsa,
    )
    if args.json:
        print(json.dumps(summary, indent=2, default=str))
    else:
        print(f"\n  {_c('green', '✓')} Sync complete")
        for feed_result in (summary.get("feeds") or []):
            print(
                f"  {feed_result.get('feed',''):<12} "
                f"{feed_result.get('records', 0):>6} records  "
                f"{feed_result.get('chunks', 0):>7} chunks  "
                f"{feed_result.get('errors', 0)} errors"
            )
        store_stats = summary.get("store_stats") or {}
        print(f"\n  Total chunks in store: {store_stats.get('total_chunks', '?'):,}")
        print()


def cmd_analyse_code(args: argparse.Namespace) -> None:
    from .rag_engine import RagEngine
    path = Path(args.file)
    if not path.exists():
        print(_c("red", f"File not found: {path}"), file=sys.stderr)
        sys.exit(1)
    code = path.read_text(errors="replace")
    language = args.language or path.suffix.lstrip(".")
    print(_c("cyan", f"  Analysing {path} ({len(code)} chars, lang={language})…"))
    engine = RagEngine()
    result = asyncio.run(engine.analyse_code(code, language=language or None, top_k=args.top_k))
    _print_result(result.to_dict(), json_output=args.json)


def cmd_analyse_manifest(args: argparse.Namespace) -> None:
    from .rag_engine import RagEngine
    path = Path(args.file)
    if not path.exists():
        print(_c("red", f"File not found: {path}"), file=sys.stderr)
        sys.exit(1)
    content = path.read_text(errors="replace")
    manifest_type = args.manifest_type or "auto"
    print(_c("cyan", f"  Analysing manifest {path} (type={manifest_type})…"))
    engine = RagEngine()
    result = asyncio.run(engine.analyse_manifest(content, manifest_type=manifest_type, top_k=args.top_k))
    _print_result(result.to_dict(), json_output=args.json)


def cmd_analyse_cve(args: argparse.Namespace) -> None:
    from .rag_engine import RagEngine
    cve_ids: List[str] = args.cve_ids
    print(_c("cyan", f"  Analysing CVEs: {', '.join(cve_ids)}…"))
    engine = RagEngine()
    result = asyncio.run(engine.analyse_cve(cve_ids, top_k=args.top_k))
    _print_result(result.to_dict(), json_output=args.json)


def cmd_analyse_vuln(args: argparse.Namespace) -> None:
    from .rag_engine import RagEngine
    vuln_data = {
        "type": args.type,
        "url": args.url,
        "parameter": args.parameter,
        "snippet": args.snippet or "",
        "library": args.library or "",
    }
    print(_c("cyan", f"  Analysing vulnerability payload ({args.type} on {args.parameter})…"))
    engine = RagEngine()
    result = asyncio.run(engine.analyse_vulnerability(vuln_data, top_k=args.top_k))
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        _print_header("Wraith Threat Intelligence — Vulnerability Deep Analysis")
        print(f"  {_c('bold', 'Description:')} {result.get('description', '')}")
        print(f"  {_c('bold', 'Impact:')} {result.get('impact', '')}")
        print(f"  {_c('bold', 'Affected Components:')} {result.get('affected_components', '')}")
        print(f"  {_c('bold', 'Remediation:')} {result.get('remediation', '')}")
        print(f"  {_c('bold', 'Payload:')} {_c('yellow', result.get('payload', ''))}")
        chain = result.get("attack_chain") or []
        if chain:
            print(f"\n  {_c('bold', 'Attack Chain:')}")
            for step in chain:
                print(f"    - {step}")
        print(f"\n  {_c('bold', 'Confidence:')} {result.get('confidence', 'N/A')}/10")
        refs = result.get("references") or []
        if refs:
            print(f"  {_c('bold', 'References:')} {', '.join(refs)}")
        print()


def cmd_query(args: argparse.Namespace) -> None:
    from .rag_engine import RagEngine
    question = " ".join(args.question)
    print(_c("cyan", f"  Query: {question[:80]}…"))
    engine = RagEngine()
    result = asyncio.run(engine.freeform_query(question, top_k=args.top_k))
    _print_result(result.to_dict(), json_output=args.json)


# ─────────────────────────────────────────────────────────────────────────────
# Argument parser
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="centrix-intel",
        description="CENTRIX Threat Intelligence — local RAG-powered vulnerability analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          centrix-intel health
          centrix-intel sync --nvd-days 30 --skip-ghsa
          centrix-intel analyse code app.py --language python
          centrix-intel analyse manifest requirements.txt
          centrix-intel analyse cve CVE-2024-1234 CVE-2023-5678
          centrix-intel analyse vuln --type "SQLi" --parameter "id" --url "http://target/api"
          centrix-intel query "What Log4j vulnerabilities are actively exploited?"
        """),
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # ── health ──────────────────────────────────────────────────────────────
    sub.add_parser("health", help="Check Ollama + ChromaDB connectivity")

    # ── status ──────────────────────────────────────────────────────────────
    sub.add_parser("status", help="Show vector store and scheduler status")

    # ── sync ────────────────────────────────────────────────────────────────
    p_sync = sub.add_parser("sync", help="Ingest latest advisories from public feeds")
    p_sync.add_argument("--nvd-days", type=int, default=7, dest="nvd_days",
                        help="Fetch NVD CVEs modified in the last N days (default: 7)")
    p_sync.add_argument("--skip-nvd", action="store_true", dest="skip_nvd")
    p_sync.add_argument("--skip-cisa", action="store_true", dest="skip_cisa")
    p_sync.add_argument("--skip-ghsa", action="store_true", dest="skip_ghsa")
    p_sync.add_argument("--json", action="store_true", help="Output JSON")

    # ── analyse ─────────────────────────────────────────────────────────────
    p_analyse = sub.add_parser("analyse", help="Analyse code, manifests, CVEs, or vulnerability data")
    analyse_sub = p_analyse.add_subparsers(dest="analyse_type", required=True)

    # analyse code
    p_code = analyse_sub.add_parser("code", help="Analyse source code file")
    p_code.add_argument("file", help="Path to the source file")
    p_code.add_argument("--language", "-l", help="Language hint (python, js, java, …)")
    p_code.add_argument("--top-k", type=int, default=8, dest="top_k")
    p_code.add_argument("--json", action="store_true")

    # analyse manifest
    p_manifest = analyse_sub.add_parser("manifest", help="Analyse dependency manifest")
    p_manifest.add_argument("file", help="Path to requirements.txt or package.json")
    p_manifest.add_argument("--type", "-t", dest="manifest_type",
                            choices=["requirements", "package.json", "auto"],
                            default="auto")
    p_manifest.add_argument("--top-k", type=int, default=8, dest="top_k")
    p_manifest.add_argument("--json", action="store_true")

    # analyse cve
    p_cve = analyse_sub.add_parser("cve", help="Analyse specific CVE IDs")
    p_cve.add_argument("cve_ids", nargs="+", help="One or more CVE IDs")
    p_cve.add_argument("--top-k", type=int, default=8, dest="top_k")
    p_cve.add_argument("--json", action="store_true")

    # analyse vuln
    p_vuln = analyse_sub.add_parser("vuln", help="Analyse a detected vulnerability record")
    p_vuln.add_argument("--type", required=True, help="Vulnerability type (e.g. SQL Injection)")
    p_vuln.add_argument("--url", default="N/A", help="Target URL")
    p_vuln.add_argument("--parameter", default="N/A", help="Target parameter")
    p_vuln.add_argument("--snippet", default="", help="Request/Response snippet")
    p_vuln.add_argument("--library", default="", help="Library version")
    p_vuln.add_argument("--top-k", type=int, default=2, dest="top_k")
    p_vuln.add_argument("--json", action="store_true")

    # ── query ───────────────────────────────────────────────────────────────
    p_query = sub.add_parser("query", help="Natural-language security question")
    p_query.add_argument("question", nargs="+", help="The question to ask")
    p_query.add_argument("--top-k", type=int, default=8, dest="top_k")
    p_query.add_argument("--json", action="store_true")

    return parser


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> None:
    # Load .env if present
    env_file = Path(__file__).resolve().parents[3] / ".env"
    if env_file.exists():
        try:
            from dotenv import load_dotenv  # type: ignore[import]
            load_dotenv(env_file)
        except ImportError:
            # Manual .env parse fallback
            import os
            for line in env_file.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    os.environ.setdefault(k.strip(), v.strip())

    parser = build_parser()
    args = parser.parse_args(argv)

    dispatch = {
        "health": cmd_health,
        "status": cmd_status,
        "sync": cmd_sync,
        "query": cmd_query,
    }

    if args.command in dispatch:
        dispatch[args.command](args)
    elif args.command == "analyse":
        analyse_dispatch = {
            "code": cmd_analyse_code,
            "manifest": cmd_analyse_manifest,
            "cve": cmd_analyse_cve,
            "vuln": cmd_analyse_vuln,
        }
        fn = analyse_dispatch.get(args.analyse_type)
        if fn:
            fn(args)
        else:
            parser.print_help()
    else:
        parser.print_help()


if __name__ == "__main__":
    if __package__ in (None, ""):
        _backend_dir = Path(__file__).resolve().parent.parent.parent
        if str(_backend_dir) not in sys.path:
            sys.path.insert(0, str(_backend_dir))
        __package__ = "scanner.threat_intel"
    main()
