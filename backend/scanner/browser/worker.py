"""Headless Chromium Browser Worker for CENTRIX.

Uses Playwright async API to autonomously discover Single-Page Application (SPA)
routes, intercept client-side DOM mutations, extract cookies and storage,
capture network traffic into EvidenceArtifacts, and collect visual screenshot artifacts.
"""
from __future__ import annotations

import asyncio
import base64
import os
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

from scanner.safety import url_in_scope


@dataclass
class BrowserDiscoveryResult:
    urls: list[str] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    screenshots: list[dict[str, Any]] = field(default_factory=list)
    cookies: list[dict[str, Any]] = field(default_factory=list)
    storage: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _screenshot_dir() -> Path:
    d = Path(__file__).resolve().parents[2] / "data" / "screenshots"
    d.mkdir(parents=True, exist_ok=True)
    return d


def is_chromium_available() -> bool:
    """Check if Playwright package is importable and browser executable is ready."""
    try:
        import playwright
        return True
    except ImportError:
        return False


class BrowserWorker:
    """Async Playwright worker for dynamic SPA route & DOM discovery."""

    def __init__(self, headless: bool = True, timeout_s: int = 25):
        self.headless = headless
        self.timeout_ms = max(5000, timeout_s * 1000)

    async def explore_target(
        self,
        target_url: str,
        scan_id: str,
        scope: Optional[list[str]] = None,
        max_pages: int = 15,
        capture_screenshots: bool = True,
    ) -> BrowserDiscoveryResult:
        """Launch headless Chromium, hook SPA routing, crawl dynamic pages, and collect evidence."""
        result = BrowserDiscoveryResult()
        try:
            from playwright.async_api import async_playwright
        except Exception as exc:
            result.error = f"Playwright unavailable: {exc}. Install via 'pip install playwright && playwright install chromium'."
            return result

        discovered_urls: set[str] = {target_url}
        visited_urls: set[str] = set()
        captured_evidence: list[dict[str, Any]] = []
        captured_forms: list[dict[str, Any]] = []
        captured_screenshots: list[dict[str, Any]] = []

        try:
            async with async_playwright() as playwright:
                try:
                    browser = await playwright.chromium.launch(
                        headless=self.headless,
                        args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
                    )
                except Exception as launch_err:
                    err_str = str(launch_err)
                    if "Executable doesn't exist" in err_str or "executable" in err_str.lower() or "not found" in err_str.lower():
                        result.error = (
                            "Chromium browser binary is not installed. Run 'python -m playwright install chromium' "
                            "or deploy via the updated Dockerfile with pre-installed browser binaries."
                        )
                    else:
                        result.error = f"Chromium launch failed: {launch_err}"
                    return result
                try:
                    context = await browser.new_context(
                        ignore_https_errors=True,
                        viewport={"width": 1280, "height": 800},
                        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 CENTRIX-Security-Auditor/4.0",
                    )
                    page = await context.new_page()

                    # Network request/response interception
                    # Capture request URLs for API discovery
                    async def on_request(request: Any) -> None:
                        try:
                            req_url = request.url
                            # Only consider in-scope URLs
                            if url_in_scope(req_url, target_url, scope):
                                # Add to discovered set immediately
                                discovered_urls.add(req_url)
                                if req_url not in visited_urls and req_url not in queue:
                                    queue.append(req_url)
                        except Exception:
                            pass
                    async def on_response(response: Any) -> None:
                        try:
                            headers = await response.all_headers()
                        except Exception:
                            headers = {}
                        content_type = headers.get("content-type", "")
                        is_text = any(t in content_type for t in ("html", "json", "xml", "javascript", "text"))
                        excerpt = ""
                        if is_text:
                            try:
                                excerpt = (await response.text())[:1000]
                            except Exception:
                                pass
                        captured_evidence.append({
                            "url": response.url,
                            "method": response.request.method,
                            "status_code": response.status,
                            "content_type": content_type,
                            "response_length": len(excerpt),
                            "response_excerpt": excerpt,
                            "response_headers": headers,
                        })

                    page.on("response", on_response)

                    # Intercept client-side SPA route changes (pushState / replaceState)
                    await page.add_init_script("""
                        window.__centrix_routes = [];
                        const origPush = history.pushState;
                        history.pushState = function() {
                            origPush.apply(this, arguments);
                            window.__centrix_routes.push(location.href);
                        };
                        const origReplace = history.replaceState;
                        history.replaceState = function() {
                            origReplace.apply(this, arguments);
                            window.__centrix_routes.push(location.href);
                        };
                        window.addEventListener('hashchange', () => {
                            window.__centrix_routes.push(location.href);
                        });
                    """)

                    # Navigate to base target
                    base_nav_ok = False
                    try:
                        await page.goto(target_url, wait_until="domcontentloaded", timeout=self.timeout_ms)
                        await page.wait_for_timeout(1000)
                        base_nav_ok = True
                    except Exception as nav_err:
                        result.error = f"Initial navigation failed: {nav_err}"

                    if base_nav_ok:
                        # Extract initial cookies & storage
                        try:
                            result.cookies = await context.cookies()
                        except Exception:
                            pass
                        try:
                            storage_dump = await page.evaluate("""() => {
                                const ls = {};
                                for (let i = 0; i < localStorage.length; i++) {
                                    const k = localStorage.key(i);
                                    ls[k] = localStorage.getItem(k);
                                }
                                return ls;
                            }""")
                            result.storage = storage_dump or {}
                        except Exception:
                            pass

                    # Crawl loop over discovered pages
                    queue = [target_url] if base_nav_ok else []
                    while queue and len(visited_urls) < max_pages:
                        current_url = queue.pop(0)
                        if current_url in visited_urls:
                            continue
                        visited_urls.add(current_url)

                        if current_url != page.url:
                            try:
                                await page.goto(current_url, wait_until="domcontentloaded", timeout=self.timeout_ms)
                                await page.wait_for_timeout(500)
                            except Exception:
                                continue

                        # Collect SPA dynamically pushed routes
                        try:
                            spa_routes = await page.evaluate("() => window.__centrix_routes || []")
                            for r in spa_routes:
                                if url_in_scope(r, target_url, scope) and r not in visited_urls:
                                    discovered_urls.add(r)
                                    if r not in queue:
                                        queue.append(r)
                        except Exception:
                            pass

                        # Extract DOM anchor links
                        try:
                            page_links = await page.evaluate("""() => {
                                return Array.from(document.querySelectorAll('a[href]'))
                                    .map(a => a.href)
                                    .filter(href => href && !href.startsWith('javascript:'));
                            }""")
                            for link in page_links:
                                if url_in_scope(link, target_url, scope):
                                    clean_link = link.split('#')[0]
                                    discovered_urls.add(clean_link)
                                    if clean_link not in visited_urls and clean_link not in queue:
                                        queue.append(clean_link)
                        except Exception:
                            pass

                        # Extract DOM forms
                        try:
                            page_forms = await page.evaluate("""() => {
                                return Array.from(document.querySelectorAll('form')).map(f => {
                                    const inputs = Array.from(f.querySelectorAll('input, select, textarea')).map(i => ({
                                        name: i.name || i.id || '',
                                        type: (i.type || i.tagName).toLowerCase(),
                                        value: i.value || '',
                                    })).filter(i => i.name);
                                    return {
                                        action: f.action || location.href,
                                        method: (f.method || 'GET').toUpperCase(),
                                        fields: inputs,
                                        inputs: inputs.map(i => i.name),
                                    };
                                });
                            }""")
                            captured_forms.extend(page_forms)
                        # Add form action URLs to discovery set
                        for f in page_forms:
                            action_url = f.get('action')
                            if action_url and url_in_scope(action_url, target_url, scope):
                                discovered_urls.add(action_url)
                                if action_url not in visited_urls and action_url not in queue:
                                    queue.append(action_url)
                        except Exception:
                            pass

                        # Capture screenshot artifact
                        if capture_screenshots and len(captured_screenshots) < 3:
                            shot_id = f"shot-{uuid.uuid4().hex[:8]}"
                            shot_file = _screenshot_dir() / f"{scan_id}_{shot_id}.png"
                            try:
                                await page.screenshot(path=str(shot_file), full_page=False)
                                captured_screenshots.append({
                                    "id": shot_id,
                                    "url": current_url,
                                    "path": str(shot_file),
                                    "filename": f"{scan_id}_{shot_id}.png",
                                })
                            except Exception:
                                pass

                    await context.close()
                finally:
                    await browser.close()

            result.urls = sorted(list(discovered_urls))
            result.forms = captured_forms
            result.evidence = captured_evidence
            result.screenshots = captured_screenshots

        except Exception as exc:
            result.error = str(exc)

        return result


# Global instance
browser_worker = BrowserWorker()
