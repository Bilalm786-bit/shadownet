"""
ShadowNet — Reverse IP / Co-hosted Domains
Lists domains hosted on the same IP using HackerTarget's free reverse-IP endpoint
(no API key, 50 req/day per source IP). Useful to find adjacent assets in shared
hosting environments.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Any, Dict, List

import aiohttp

from app.modules.base import EntityFound, ModuleRegistry, OSINTModule, ScanResult


class ReverseIPLookup(OSINTModule):
    name = "recon.reverse_ip"
    description = "Discover other domains hosted on the same IP (HackerTarget free)"
    supported_target_types = ["ip", "domain"]
    requires_api_key = False
    rate_limit = 5

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        target = target.strip().lower()
        ip = await self._resolve(target)
        if not ip:
            return ScanResult(module=self.name, target=target, success=False,
                              error=f"Could not resolve {target} to an IP")

        domains: List[str] = []
        raw: Dict[str, Any] = {"ip": ip, "domains": []}

        try:
            url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                    text = await resp.text()
                    if resp.status == 200 and "error" not in text.lower() and "API count exceeded" not in text:
                        for line in text.splitlines():
                            host = line.strip().lower()
                            if host and "." in host and host != target:
                                domains.append(host)
        except Exception as exc:
            raw["error"] = str(exc)

        domains = sorted(set(domains))[:200]
        raw["domains"] = domains

        entities = [
            EntityFound(
                entity_type="domain", value=d, source=self.name, confidence=0.85,
                metadata={"co_hosted_on": ip},
                relationships=[{"type": "CO_HOSTED_WITH", "target": target}],
            )
            for d in domains
        ]

        severity = "medium" if len(domains) > 50 else "info"
        summary = f"Reverse-IP for {target} ({ip}): {len(domains)} co-hosted domains found"

        return ScanResult(
            module=self.name, target=target, success=True,
            entities=entities, raw_data=raw, summary=summary, severity=severity,
        )

    @staticmethod
    async def _resolve(target: str) -> str | None:
        try:
            socket.inet_aton(target)
            return target
        except OSError:
            pass
        try:
            info = await asyncio.get_event_loop().run_in_executor(
                None, socket.getaddrinfo, target, None, socket.AF_INET
            )
            return info[0][4][0] if info else None
        except Exception:
            return None


ModuleRegistry.register(ReverseIPLookup())
