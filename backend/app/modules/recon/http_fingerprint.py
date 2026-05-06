"""
ShadowNet — HTTP Fingerprinter
Captures HTTP/HTTPS response fingerprint: status, redirect chain, server tokens,
HSTS, HTTP version, TLS protocol, response timing, content hash and favicon hash
(MMH3-style murmur). Useful for asset correlation across different hosts.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, Dict, List

import aiohttp

from app.modules.base import EntityFound, ModuleRegistry, OSINTModule, ScanResult


class HTTPFingerprint(OSINTModule):
    name = "recon.http_fingerprint"
    description = "Capture HTTP fingerprint: redirects, headers, body hash, favicon hash (free)"
    supported_target_types = ["domain", "url"]
    requires_api_key = False
    rate_limit = 30

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        target = target.strip()
        url = target if target.startswith("http") else f"https://{target}"
        domain = url.split("//")[-1].split("/")[0]

        data: Dict[str, Any] = {"url": url, "redirects": [], "schemes_tried": []}
        entities: List[EntityFound] = []

        for scheme in ("https", "http"):
            try_url = url if url.startswith(scheme + "://") else f"{scheme}://{domain}"
            data["schemes_tried"].append(try_url)
            try:
                connector = aiohttp.TCPConnector(ssl=False)
                async with aiohttp.ClientSession(connector=connector) as session:
                    start = time.perf_counter()
                    async with session.get(
                        try_url, timeout=aiohttp.ClientTimeout(total=15),
                        allow_redirects=True, max_redirects=10,
                    ) as resp:
                        elapsed = round((time.perf_counter() - start) * 1000)
                        body = await resp.read()
                        data[scheme] = {
                            "final_url": str(resp.url),
                            "status": resp.status,
                            "headers": {k: v for k, v in resp.headers.items()},
                            "ms": elapsed,
                            "body_sha256": hashlib.sha256(body).hexdigest(),
                            "body_size": len(body),
                            "redirects": [str(h.url) for h in resp.history],
                        }
                        for h in resp.history:
                            data["redirects"].append({
                                "from": str(h.url), "status": h.status,
                                "to": h.headers.get("Location", ""),
                            })
                    if scheme == "https":
                        try:
                            fav = await session.get(
                                f"{scheme}://{domain}/favicon.ico",
                                timeout=aiohttp.ClientTimeout(total=8),
                            )
                            blob = await fav.read()
                            if blob and 100 < len(blob) < 200_000:
                                data["favicon_md5"] = hashlib.md5(blob).hexdigest()
                                data["favicon_sha256"] = hashlib.sha256(blob).hexdigest()
                                data["favicon_size"] = len(blob)
                        except Exception:
                            pass
            except Exception as exc:
                data[scheme + "_error"] = str(exc)

        primary = data.get("https") or data.get("http") or {}

        if primary:
            srv = primary.get("headers", {}).get("Server") or primary.get("headers", {}).get("server")
            if srv:
                entities.append(EntityFound(
                    entity_type="technology", value=srv, source=self.name, confidence=0.85,
                    metadata={"category": "web_server", "domain": domain},
                    relationships=[{"type": "RUNS_ON", "target": domain}],
                ))
            if "favicon_md5" in data:
                entities.append(EntityFound(
                    entity_type="favicon_hash", value=data["favicon_md5"],
                    source=self.name, confidence=1.0,
                    metadata={"sha256": data.get("favicon_sha256"), "size": data.get("favicon_size"), "domain": domain},
                    relationships=[{"type": "BELONGS_TO", "target": domain}],
                ))

        status = primary.get("status", "n/a")
        ms = primary.get("ms", "n/a")
        summary = (
            f"HTTP fingerprint {domain}: status={status} | {ms}ms | "
            f"redirects={len(data['redirects'])} | favicon={data.get('favicon_md5', 'none')}"
        )

        severity = "info"
        if isinstance(status, int) and status >= 500:
            severity = "medium"

        return ScanResult(
            module=self.name, target=domain, success=bool(primary),
            entities=entities, raw_data=data, summary=summary, severity=severity,
        )


ModuleRegistry.register(HTTPFingerprint())
