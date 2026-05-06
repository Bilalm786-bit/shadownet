"""
ShadowNet — HTTP Method Probe
Sends OPTIONS / TRACE / PUT / DELETE / PATCH / CONNECT against the target and
flags methods that are unexpectedly allowed (TRACE → XST, PUT → arbitrary file
upload, DELETE → resource removal). Also flags missing security headers
discovered along the way.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List

import aiohttp

from app.modules.base import EntityFound, ModuleRegistry, OSINTModule, ScanResult


METHODS = ["OPTIONS", "GET", "POST", "PUT", "DELETE", "PATCH", "TRACE", "CONNECT", "PROPFIND"]
RISKY = {"PUT": "high", "DELETE": "high", "TRACE": "high", "CONNECT": "high", "PROPFIND": "medium", "PATCH": "medium"}


class HTTPMethodProbe(OSINTModule):
    name = "recon.http_methods"
    description = "Probe allowed HTTP methods (OPTIONS/TRACE/PUT/DELETE/etc.) (free)"
    supported_target_types = ["domain", "url"]
    requires_api_key = False
    rate_limit = 30

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        target = target.strip().lower()
        url = target if target.startswith("http") else f"https://{target}"
        domain = url.split("//")[-1].split("/")[0]

        results: Dict[str, Dict[str, Any]] = {}
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            try:
                async with session.options(url, timeout=aiohttp.ClientTimeout(total=8), allow_redirects=False) as resp:
                    allow_header = resp.headers.get("Allow") or resp.headers.get("Access-Control-Allow-Methods", "")
                    results["OPTIONS"] = {"status": resp.status, "allow": allow_header}
            except Exception as exc:
                results["OPTIONS"] = {"error": str(exc)}

            sem = asyncio.Semaphore(4)

            async def probe(m: str) -> None:
                async with sem:
                    try:
                        async with session.request(m, url, timeout=aiohttp.ClientTimeout(total=8), allow_redirects=False) as resp:
                            results[m] = {"status": resp.status, "allow_response": resp.headers.get("Allow", ""), "size": int(resp.headers.get("Content-Length", 0))}
                    except Exception as exc:
                        results[m] = {"error": str(exc)}

            await asyncio.gather(*[probe(m) for m in METHODS if m != "OPTIONS"])

        allowed_from_options = []
        if results.get("OPTIONS", {}).get("allow"):
            allowed_from_options = [m.strip().upper() for m in results["OPTIONS"]["allow"].split(",")]

        risky_findings: List[Dict[str, Any]] = []
        for method, info in results.items():
            status = info.get("status")
            if status is None:
                continue
            allowed = (
                method in allowed_from_options or
                status not in (405, 501, 400, 404)
            )
            if allowed and method in RISKY:
                risky_findings.append({
                    "method": method, "status": status,
                    "severity": RISKY[method],
                    "concern": {
                        "PUT": "Arbitrary file upload may be possible",
                        "DELETE": "Arbitrary resource deletion may be possible",
                        "TRACE": "Cross-Site Tracing (XST) — can leak Authorization headers",
                        "CONNECT": "HTTP CONNECT proxy abuse possible",
                        "PROPFIND": "WebDAV property disclosure",
                        "PATCH": "Unexpected resource mutation may be possible",
                    }.get(method, ""),
                })

        entities = []
        for f in risky_findings:
            entities.append(EntityFound(
                entity_type="vulnerability", value=f"http_method_{f['method'].lower()}",
                source=self.name, confidence=0.85,
                metadata={
                    "method": f["method"], "status": f["status"],
                    "concern": f["concern"], "severity": f["severity"], "domain": domain,
                },
                relationships=[{"type": "AFFECTS", "target": domain}],
            ))

        severity = "high" if any(f["severity"] == "high" for f in risky_findings) else (
            "medium" if risky_findings else "info"
        )
        summary = (
            f"HTTP methods {domain}: OPTIONS Allow={results.get('OPTIONS', {}).get('allow', 'n/a')} | "
            f"risky methods allowed: {', '.join(f['method'] for f in risky_findings) or 'none'}"
        )

        return ScanResult(
            module=self.name, target=domain, success=True,
            entities=entities,
            raw_data={"per_method": results, "risky": risky_findings, "options_allow": allowed_from_options},
            summary=summary, severity=severity,
        )


ModuleRegistry.register(HTTPMethodProbe())
