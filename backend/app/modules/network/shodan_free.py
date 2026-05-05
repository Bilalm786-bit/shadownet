"""
ShadowNet — Shodan InternetDB (Free, No Key)
Uses https://internetdb.shodan.io/{ip} — completely free, no API key.
Returns: open ports, hostnames, CPEs, vulns, tags for any IP address.
"""

import aiohttp
import socket
from typing import Dict, Any
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry
import structlog

logger = structlog.get_logger(__name__)


class ShodanFree(OSINTModule):
    name = "network.shodan_free"
    description = "Shodan InternetDB — free vulnerability and port data for any IP (no API key)"
    supported_target_types = ["ip", "domain"]
    requires_api_key = False
    rate_limit = 10

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        target = target.strip()
        ip = target
        entities = []

        # Resolve domain to IP if needed
        try:
            info = socket.getaddrinfo(target, None, socket.AF_INET)
            if info:
                ip = info[0][4][0]
        except Exception:
            pass

        headers = {"User-Agent": "ShadowNet-OSINT", "Accept": "application/json"}
        connector = aiohttp.TCPConnector(ssl=False)

        try:
            async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
                url = f"https://internetdb.shodan.io/{ip}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 404:
                        return ScanResult(
                            module=self.name, target=target, success=True,
                            raw_data={"ip": ip, "message": "No data found in Shodan InternetDB"},
                            summary=f"Shodan InternetDB: No data for {ip}",
                            severity="info",
                        )
                    if resp.status != 200:
                        return ScanResult(
                            module=self.name, target=target, success=False,
                            error=f"Shodan InternetDB returned HTTP {resp.status}",
                        )

                    data = await resp.json()
        except Exception as e:
            return ScanResult(module=self.name, target=target, success=False, error=str(e))

        # Parse results
        ports = data.get("ports", [])
        hostnames = data.get("hostnames", [])
        cpes = data.get("cpes", [])
        vulns = data.get("vulns", [])
        tags = data.get("tags", [])

        # Build entities
        for hostname in hostnames:
            entities.append(EntityFound(
                entity_type="domain", value=hostname, source=self.name, confidence=0.95,
                metadata={"ip": ip, "source": "shodan_internetdb"},
                relationships=[{"type": "RESOLVES_TO", "target": ip}],
            ))

        for vuln in vulns:
            entities.append(EntityFound(
                entity_type="vulnerability", value=vuln, source=self.name, confidence=0.85,
                metadata={"ip": ip, "cve": vuln},
                relationships=[{"type": "VULNERABLE_TO", "target": ip}],
            ))

        for port in ports:
            entities.append(EntityFound(
                entity_type="service", value=f"{ip}:{port}", source=self.name, confidence=0.95,
                metadata={"port": port, "ip": ip},
                relationships=[{"type": "EXPOSES_PORT", "target": ip}],
            ))

        # Severity based on vulns
        severity = "critical" if vulns else ("high" if len(ports) > 10 else "medium" if ports else "info")

        summary_parts = [f"Shodan InternetDB: {ip}"]
        if ports:
            summary_parts.append(f"Ports: {', '.join(str(p) for p in ports[:15])}")
        if hostnames:
            summary_parts.append(f"Hostnames: {', '.join(hostnames[:5])}")
        if vulns:
            summary_parts.append(f"⚠️ Vulns: {', '.join(vulns[:10])}")
        if cpes:
            summary_parts.append(f"CPEs: {len(cpes)}")
        if tags:
            summary_parts.append(f"Tags: {', '.join(tags)}")

        return ScanResult(
            module=self.name, target=target, success=True,
            entities=entities,
            raw_data={
                "ip": ip, "ports": ports, "hostnames": hostnames,
                "cpes": cpes, "vulns": vulns, "tags": tags,
            },
            summary=" | ".join(summary_parts),
            severity=severity,
        )


ModuleRegistry.register(ShodanFree())
