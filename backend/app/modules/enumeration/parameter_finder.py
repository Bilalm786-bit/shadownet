"""
ShadowNet — Parameter Finder
Crawls the target landing page (and a handful of internal links), extracts all
URL query parameters, form input names, JSON keys from inline scripts and links
to JS files, and merges them into a deduplicated parameter dictionary. Useful
seed for further fuzzing.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List, Set
from urllib.parse import parse_qs, urljoin, urlparse

import aiohttp

from app.modules.base import EntityFound, ModuleRegistry, OSINTModule, ScanResult


PARAM_QS_RE = re.compile(r"\?([^\"'\s>]+)")
HTML_INPUT_RE = re.compile(r"<input[^>]*name=[\"']([^\"']+)[\"']", re.I)
HTML_TEXTAREA_RE = re.compile(r"<textarea[^>]*name=[\"']([^\"']+)[\"']", re.I)
HTML_SELECT_RE = re.compile(r"<select[^>]*name=[\"']([^\"']+)[\"']", re.I)
JS_KEY_RE = re.compile(r'["\']([a-zA-Z_][a-zA-Z0-9_]{2,40})["\']\s*:')
JS_LINK_RE = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.I)
LINK_RE = re.compile(r'href=["\']([^"\']+)["\']', re.I)


class ParameterFinder(OSINTModule):
    name = "enumeration.parameter_finder"
    description = "Discover URL/form/JSON parameter names from the target site (free)"
    supported_target_types = ["domain", "url"]
    requires_api_key = False
    rate_limit = 10

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        options = options or {}
        target = target.strip().lower()
        url_base = target if target.startswith("http") else f"https://{target}"
        domain = urlparse(url_base).netloc
        max_pages = min(int(options.get("max_pages", 12)), 25)

        params: Set[str] = set()
        endpoints_with_params: List[str] = []
        js_files: Set[str] = set()
        sem = asyncio.Semaphore(8)

        async def fetch(session: aiohttp.ClientSession, url: str) -> str:
            async with sem:
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False, allow_redirects=True) as resp:
                        if "text" not in resp.headers.get("Content-Type", "") and "javascript" not in resp.headers.get("Content-Type", ""):
                            return ""
                        return await resp.text(errors="ignore")
                except Exception:
                    return ""

        connector = aiohttp.TCPConnector(ssl=False, limit=10)
        async with aiohttp.ClientSession(connector=connector) as session:
            home = await fetch(session, url_base)
            self._extract_from_html(home, url_base, domain, params, endpoints_with_params, js_files)

            internal: List[str] = []
            for href in LINK_RE.findall(home or ""):
                full = urljoin(url_base, href).split("#")[0]
                if urlparse(full).netloc == domain and full not in internal and len(internal) < max_pages:
                    internal.append(full)

            for url in internal[:max_pages]:
                body = await fetch(session, url)
                self._extract_from_html(body, url, domain, params, endpoints_with_params, js_files)

            for js in list(js_files)[:15]:
                body = await fetch(session, js)
                for m in JS_KEY_RE.findall(body or ""):
                    params.add(m)
                for m in PARAM_QS_RE.findall(body or ""):
                    self._extract_qs(m, params)

        params_sorted = sorted(p for p in params if 2 <= len(p) <= 60 and re.match(r"^[a-zA-Z_][a-zA-Z0-9_\-]*$", p))[:500]

        entities = [
            EntityFound(
                entity_type="parameter", value=p, source=self.name, confidence=0.7,
                metadata={"domain": domain},
                relationships=[{"type": "ACCEPTED_BY", "target": domain}],
            ) for p in params_sorted[:200]
        ]

        summary = (
            f"Parameters discovered on {domain}: {len(params_sorted)} unique names | "
            f"{len(endpoints_with_params)} endpoints with query strings | "
            f"{len(js_files)} JS files inspected"
        )

        return ScanResult(
            module=self.name, target=domain, success=True,
            entities=entities,
            raw_data={
                "params": params_sorted,
                "endpoints_with_params": endpoints_with_params[:200],
                "js_files": sorted(js_files)[:50],
            },
            summary=summary,
            severity="medium" if len(endpoints_with_params) > 10 else "info",
        )

    @staticmethod
    def _extract_from_html(body: str, source_url: str, domain: str,
                           params: Set[str], endpoints_with_params: List[str], js_files: Set[str]) -> None:
        if not body:
            return
        for m in HTML_INPUT_RE.findall(body):
            params.add(m)
        for m in HTML_TEXTAREA_RE.findall(body):
            params.add(m)
        for m in HTML_SELECT_RE.findall(body):
            params.add(m)
        for js in JS_LINK_RE.findall(body):
            full = urljoin(source_url, js)
            if urlparse(full).netloc == domain:
                js_files.add(full)
        for href in LINK_RE.findall(body):
            full = urljoin(source_url, href)
            qs = urlparse(full).query
            if qs and urlparse(full).netloc == domain:
                if full not in endpoints_with_params and len(endpoints_with_params) < 200:
                    endpoints_with_params.append(full)
                ParameterFinder._extract_qs(qs, params)

    @staticmethod
    def _extract_qs(qs: str, params: Set[str]) -> None:
        for k in parse_qs(qs).keys():
            params.add(k)


ModuleRegistry.register(ParameterFinder())
