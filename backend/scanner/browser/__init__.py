"""Browser package for headless Chromium exploration and DOM analysis."""
from .worker import BrowserWorker, BrowserDiscoveryResult, browser_worker

__all__ = ["BrowserWorker", "BrowserDiscoveryResult", "browser_worker"]
