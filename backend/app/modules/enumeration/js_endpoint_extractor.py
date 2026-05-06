"""
ShadowNet — JS Endpoint Extractor
Walks <script src=…> URLs from the landing page and harvests API endpoints,
absolute and relative paths, AWS keys (regex-fingerprint only), and any embedded
links. Heavily reduces the manual work of grepping minified JS bundles.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List, Set
from urllib.parse import urljoin, urlparse

import aiohttp

from app.modules.base import EntityFound, ModuleRegistry, OSINTModule, ScanResult


SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.I)
INLINE_SCRIPT_RE = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.I | re.S)
ENDPOINT_RE = re.compile(
    r'(?<![\w/])(?:["\'`])(/(?:[a-zA-Z0-9_\-./{}]+))(?:["\'`])'
)
URL_RE = re.compile(
    r'https?://[a-zA-Z0-9._:\-]+(?:/[a-zA-Z0-9._\-/?&%=#]*)?'
)
SECRET_PATTERNS: Dict[str, re.Pattern] = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_key": re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,48}"),
    "stripe_key": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    "private_key_block": re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"),
}


class JSEndpointExtractor(OSINTModule):
    name = "enumeration.js_endpoints"
    description = "Walk JS bundles to extract endpoints, URLs, secrets and SaaS keys (free)"
    supported_target_types = ["domain", "url"]
    requires_api_key = False
    rate_limit = 5

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        options = options or {}
        target = target.strip().lower()
        url_base = target if target.startswith("http") else f"https://{target}"
        domain = urlparse(url_base).netloc
        max_files = min(int(options.get("max_files", 20)), 40)

        endpoints: Set[str] = set()
        urls: Set[str] = set()
        secrets: List[Dict[str, Any]] = []
        js_files: List[str] = []

        connector = aiohttp.TCPConnector(ssl=False, limit=10)
        async with aiohttp.ClientSession(connector=connector) as session:
            home = await self._fetch(session, url_base)
            for src in SCRIPT_SRC_RE.findall(home or ""):
                full = urljoin(url_base, src)
                if full not in js_files and len(js_files) < max_files:
                    js_files.append(full)
            for inline in INLINE_SCRIPT_RE.findall(home or ""):
                self._mine(inline, url_base, endpoints, urls, secrets)

            sem = asyncio.Semaphore(6)

            async def grab(js_url: str) -> None:
                async with sem:
                    blob = await self._fetch(session, js_url)
                    if blob:
                        self._mine(blob, js_url, endpoints, urls, secrets)

            await asyncio.gather(*[grab(j) for j in js_files])

        endpoints_list = sorted(e for e in endpoints if 2 <= len(e) <= 200)[:500]
        urls_list = sorted(urls)[:500]

        entities: List[EntityFound] = []
        for ep in endpoints_list[:200]:
            entities.append(EntityFound(
                entity_type="api_endpoint", value=ep, source=self.name, confidence=0.7,
                metadata={"domain": domain},
                relationships=[{"type": "EXPOSES", "target": domain}],
            ))
        for s in secrets:
            entities.append(EntityFound(
                entity_type="leaked_secret", value=s["match_preview"], source=self.name,
                confidence=0.95,
                metadata={"kind": s["kind"], "found_in": s["source_url"]},
                relationships=[{"type": "LEAKED_IN", "target": s["source_url"]}],
            ))

        severity = "critical" if any(s["kind"] in ("aws_access_key", "private_key_block", "stripe_key", "google_api_key") for s in secrets) else (
            "high" if secrets else ("medium" if len(endpoints_list) > 25 else "info")
        )

        summary = (
            f"JS-Endpoints on {domain}: {len(js_files)} JS files | "
            f"{len(endpoints_list)} endpoints | {len(urls_list)} URLs | "
            f"{len(secrets)} potential secrets"
        )

        return ScanResult(
            module=self.name, target=domain, success=True,
            entities=entities,
            raw_data={
                "js_files": js_files,
                "endpoints": endpoints_list,
                "urls": urls_list,
                "secrets": secrets,
            },
            summary=summary, severity=severity,
        )

    @staticmethod
    async def _fetch(session: aiohttp.ClientSession, url: str) -> str:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=12), ssl=False, allow_redirects=True) as resp:
                ct = resp.headers.get("Content-Type", "")
                if resp.status != 200:
                    return ""
                if "text" not in ct and "javascript" not in ct and "json" not in ct:
                    return ""
                if int(resp.headers.get("Content-Length", "0") or 0) > 4_000_000:
                    return ""
                return await resp.text(errors="ignore")
        except Exception:
            return ""

    @staticmethod
    def _mine(blob: str, source_url: str, endpoints: Set[str], urls: Set[str], secrets: List[Dict[str, Any]]) -> None:
        for m in ENDPOINT_RE.findall(blob):
            endpoints.add(m)
        for m in URL_RE.findall(blob):
            urls.add(m)
        for kind, pattern in SECRET_PATTERNS.items():
            for match in pattern.findall(blob):
                preview = match if len(match) <= 80 else match[:40] + "…" + match[-10:]
                secrets.append({
                    "kind": kind,
                    "match_preview": preview,
                    "source_url": source_url,
                })


ModuleRegistry.register(JSEndpointExtractor())
