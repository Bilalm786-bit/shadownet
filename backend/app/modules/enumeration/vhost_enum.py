"""
ShadowNet — Virtual Host Enumeration
Probes the target IP with different Host: headers from a built-in candidate list
to find virtual hosts that respond with different content sizes than the default.
Useful for uncovering staging / internal sites bound to the same IP.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Any, Dict, List

import aiohttp

from app.modules.base import EntityFound, ModuleRegistry, OSINTModule, ScanResult


CANDIDATE_PREFIXES = [
    "admin", "api", "app", "auth", "backup", "beta", "dev", "developer", "git",
    "internal", "intranet", "jenkins", "jira", "kibana", "lab", "manage", "mail",
    "monitor", "old", "panel", "preview", "private", "qa", "release", "secret",
    "staging", "test", "uat", "vpn", "wiki",
]


class VhostEnum(OSINTModule):
    name = "enumeration.vhost_enum"
    description = "Virtual host discovery via Host header fuzzing on the target's IP (free)"
    supported_target_types = ["ip", "domain"]
    requires_api_key = False
    rate_limit = 5

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        options = options or {}
        target = target.strip().lower()
        domain = target.split("//")[-1].split("/")[0]

        ip = await self._resolve(domain)
        if not ip:
            return ScanResult(module=self.name, target=target, success=False,
                              error=f"Could not resolve {target}")

        prefixes: List[str] = options.get("prefixes") or CANDIDATE_PREFIXES
        candidates: List[str] = options.get("candidates") or [f"{p}.{domain}" for p in prefixes]
        candidates += [f"{p}-{domain}" for p in prefixes[:8]]

        baseline = await self._probe(ip, "shadownet-baseline.invalid")
        baseline_size = baseline["size"] if baseline else -1
        baseline_status = baseline["status"] if baseline else 0

        findings: List[Dict[str, Any]] = []
        sem = asyncio.Semaphore(20)

        async def run(host: str) -> None:
            async with sem:
                res = await self._probe(ip, host)
                if not res:
                    return
                interesting = (
                    res["status"] in (200, 301, 302, 401, 403) and
                    not (res["status"] == baseline_status and abs(res["size"] - baseline_size) < 64)
                )
                if interesting:
                    findings.append({"vhost": host, **res})

        await asyncio.gather(*[run(h) for h in sorted(set(candidates))])

        entities = [
            EntityFound(
                entity_type="vhost", value=f["vhost"], source=self.name, confidence=0.85,
                metadata={"ip": ip, "status": f["status"], "size": f["size"]},
                relationships=[{"type": "HOSTED_AT", "target": ip}],
            )
            for f in findings
        ]

        severity = "high" if len(findings) > 5 else ("medium" if findings else "info")
        summary = (
            f"VhostEnum on {ip}: {len(findings)} new virtual hosts found "
            f"out of {len(candidates)} probed (baseline status={baseline_status} size={baseline_size})"
        )

        return ScanResult(
            module=self.name, target=domain, success=True,
            entities=entities,
            raw_data={"ip": ip, "baseline": baseline, "findings": findings, "tested": len(candidates)},
            summary=summary, severity=severity,
        )

    @staticmethod
    async def _resolve(host: str) -> str | None:
        try:
            socket.inet_aton(host)
            return host
        except OSError:
            pass
        try:
            info = await asyncio.get_event_loop().run_in_executor(
                None, socket.getaddrinfo, host, None, socket.AF_INET
            )
            return info[0][4][0] if info else None
        except Exception:
            return None

    @staticmethod
    async def _probe(ip: str, host_header: str) -> Dict[str, Any] | None:
        url = f"http://{ip}/"
        headers = {"Host": host_header, "User-Agent": "ShadowNet/2 VHostEnum"}
        try:
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=8), allow_redirects=False) as resp:
                    body = await resp.read()
                    return {
                        "status": resp.status,
                        "size": len(body),
                        "content_type": resp.headers.get("Content-Type", ""),
                        "server": resp.headers.get("Server", ""),
                    }
        except Exception:
            return None


ModuleRegistry.register(VhostEnum())
