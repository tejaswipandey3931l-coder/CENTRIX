"""CENTRIX Agent Policy Engine.

Enforces scope enforcement, RFC1918/link-local blocking, step/request limits,
and mandatory human-in-the-loop (HITL) approval gates.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Optional
from urllib.parse import urlparse

from .config import cfg
from .errors import PolicyViolationError


# Actions that strictly require human approval
APPROVAL_REQUIRED_TOOLS = {
    "run_scanner_module",
    "run_scanner_profile",
    "run_nuclei",
    "create_proof_task",
    "run_proof_task",
    "replay_request",
    "submit_browser_form",
    "fill_browser_field",
    "click_browser_element",
}

# Passive, safe tools that can execute without human approval
PASSIVE_SAFE_TOOLS = {
    "validate_target",
    "confirm_authorization",
    "create_assessment_plan",
    "crawl_target",
    "discover_endpoints",
    "discover_forms",
    "analyze_technologies",
    "launch_browser",
    "close_browser",
    "navigate_browser",
    "inspect_page",
    "capture_browser_state",
    "capture_screenshot",
    "capture_network_requests",
    "list_captured_requests",
    "inspect_request",
    "compare_requests",
    "save_request_to_corpus",
    "run_passive_analysis",
    "select_scanner_modules",
    "collect_evidence",
    "search_threat_intelligence",
    "enrich_finding",
    "generate_report",
    "get_scan_status",
    "get_browser_status",
    "get_proxy_status",
    "pause_agent",
    "resume_agent",
    "stop_agent",
}

BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"), # Link-local / Cloud metadata (AWS/GCP/Azure)
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


class PolicyEngine:
    def __init__(self):
        self.max_steps = cfg.ai_max_steps
        self.max_requests = cfg.ai_max_requests_per_scan
        self.max_concurrent = cfg.ai_max_concurrent_requests
        self.require_approvals = cfg.ai_require_approval_for_active_tests

    def validate_target_scope(self, target_url: str, allowed_domains: Optional[list[str]] = None) -> bool:
        """Validates that target URL is a valid http/https endpoint and does not hit prohibited infrastructure."""
        if not target_url:
            raise PolicyViolationError("Target URL cannot be empty.")

        parsed = urlparse(target_url)
        if parsed.scheme not in ("http", "https"):
            raise PolicyViolationError(f"Prohibited protocol '{parsed.scheme}'. Only http and https are permitted.")

        hostname = parsed.hostname
        if not hostname:
            raise PolicyViolationError(f"Invalid URL structure: {target_url}")

        # Check for IP literal
        try:
            ip = ipaddress.ip_address(hostname)
            for net in BLOCKED_IP_NETWORKS:
                if ip in net:
                    raise PolicyViolationError(
                        f"Target IP {ip} is in a prohibited private or link-local range ({net}). "
                        f"Direct scanning of cloud metadata or internal subnets is blocked."
                    )
        except ValueError:
            # hostname is domain name, verify not matching loopback/metadata
            if hostname.lower() in ("localhost", "metadata.google.internal", "instance-data"):
                raise PolicyViolationError(f"Target host '{hostname}' is prohibited.")

        # If allowed_domains scope whitelist is set
        if allowed_domains:
            matched = any(
                hostname == domain or hostname.endswith(f".{domain}")
                for domain in allowed_domains
            )
            if not matched:
                raise PolicyViolationError(
                    f"Target host '{hostname}' is outside the authorized domain scope: {allowed_domains}"
                )

        return True

    def is_approval_required(self, tool_name: str, safety_profile: str = "passive") -> bool:
        """Determines if a tool requires explicit human approval."""
        if not self.require_approvals:
            return False

        if tool_name in APPROVAL_REQUIRED_TOOLS:
            return True

        if safety_profile == "strict_approval" and tool_name not in PASSIVE_SAFE_TOOLS:
            return True

        return False

    def check_step_limit(self, current_step: int) -> None:
        """Enforces maximum agent step limit."""
        if current_step >= self.max_steps:
            raise PolicyViolationError(
                f"Agent exceeded maximum step limit ({self.max_steps}). Execution halted safely."
            )

    def check_request_limit(self, total_requests: int) -> None:
        """Enforces request budget."""
        if total_requests >= self.max_requests:
            raise PolicyViolationError(
                f"Scan reached maximum request budget ({self.max_requests}). Active operations halted."
            )

    def sanitize_untrusted_content(self, raw_content: str) -> str:
        """
        Guards against indirect prompt injection in scraped web content / DOM.
        Neutralizes instruction markers and caps length.
        """
        if not isinstance(raw_content, str):
            return ""

        # Truncate large blobs
        content = raw_content[:30000]

        # Neutralize common prompt injection delimiters / override instructions
        patterns = [
            r"(\bignore previous instructions\b)",
            r"(\bsystem prompt override\b)",
            r"(\bdisregard all previous\b)",
            r"(\bnew system instructions\b)",
            r"(<\|im_start\|>)",
            r"(<\|im_end\|>)",
            r"(\[INST\])",
            r"(\[/INST\])",
        ]
        for pattern in patterns:
            content = re.sub(pattern, "[UNTRUSTED_PATTERN_STRIPPED]", content, flags=re.IGNORECASE)

        return content


policy_engine = PolicyEngine()
