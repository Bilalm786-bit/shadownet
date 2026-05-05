"""
ShadowNet — Async Port Scanner Module
Real port scanning via async socket connections with banner grabbing.
"""

import asyncio
import socket
from typing import Dict, Any, List, Optional
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry
import structlog

logger = structlog.get_logger(__name__)

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 587: "SMTP-Sub", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
    11211: "Memcached", 6667: "IRC", 8000: "HTTP-Dev", 9000: "MinIO",
    389: "LDAP", 636: "LDAPS", 161: "SNMP", 5672: "AMQP",
}

RISKY_PORTS = {21, 23, 445, 3389, 5900, 6379, 27017, 9200, 11211, 1433, 5432, 3306}


class PortScanner(OSINTModule):
    name = "network.port_scanner"
    description = "Async TCP port scanner with banner grabbing and vulnerability detection"
    supported_target_types = ["ip", "domain"]
    requires_api_key = False

    async def _scan_port(self, host: str, port: int, timeout: float = 3.0) -> Optional[Dict]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            banner = ""
            try:
                if port in (80, 8080, 8000):
                    writer.write(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                else:
                    writer.write(b"\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                banner = data.decode("utf-8", errors="ignore").strip()[:300]
            except Exception:
                pass
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            result = {"port": port, "state": "open", "service": COMMON_PORTS.get(port, "Unknown"), "banner": banner or None}
            if port in RISKY_PORTS:
                result["risk"] = "high"
                result["warning"] = f"Port {port} ({result['service']}) should not be internet-exposed"
            return result
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        target = target.strip()
        ip = target
        try:
            info = socket.getaddrinfo(target, None, socket.AF_INET)
            if info:
                ip = info[0][4][0]
        except Exception:
            pass

        ports = sorted(COMMON_PORTS.keys())
        semaphore = asyncio.Semaphore(50)

        async def limited(port):
            async with semaphore:
                return await self._scan_port(ip, port)

        results = await asyncio.gather(*[limited(p) for p in ports])
        open_ports = sorted([r for r in results if r], key=lambda x: x["port"])

        entities = []
        for p in open_ports:
            entities.append(EntityFound(
                entity_type="service", value=f"{target}:{p['port']} ({p['service']})",
                source=self.name, confidence=1.0,
                metadata={"port": p["port"], "service": p["service"], "banner": p.get("banner"), "risk": p.get("risk")},
                relationships=[{"type": "EXPOSES_SERVICE", "target": target}],
            ))

        risky = [p for p in open_ports if p.get("risk")]
        severity = "high" if risky else ("medium" if len(open_ports) > 15 else "info")
        port_list = ", ".join(f"{p['port']}/{p['service']}" for p in open_ports[:15])
        summary = f"Port scan {target} ({ip}): {len(open_ports)} open / {len(ports)} scanned | {port_list}"
        if risky:
            summary += f" | ⚠️ {len(risky)} risky services exposed"

        return ScanResult(
            module=self.name, target=target, success=True, entities=entities,
            raw_data={"host": target, "ip": ip, "open_ports": open_ports, "open_count": len(open_ports)},
            summary=summary, severity=severity,
        )


ModuleRegistry.register(PortScanner())
