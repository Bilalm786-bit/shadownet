"""
ShadowNet — VirusTotal Scanner Module
Uses the VirusTotal API v3 for IP/domain/URL reputation, malware detection,
SSL certificates, and threat intelligence.
"""

import aiohttp
import asyncio
from typing import Dict, Any, List
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry
from app.core.config import settings
import structlog

logger = structlog.get_logger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalScanner(OSINTModule):
    name = "network.virustotal"
    description = "VirusTotal API — malware scanning, IP/domain/URL reputation, threat intelligence"
    supported_target_types = ["domain", "ip", "url"]
    requires_api_key = True
    rate_limit = 4  # free tier: 4 req/min

    def _headers(self):
        return {"x-apikey": settings.virustotal_api_key, "Accept": "application/json"}

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        target = target.strip()
        if not settings.virustotal_api_key:
            return ScanResult(
                module=self.name, target=target, success=False,
                error="VirusTotal API key not configured",
            )

        entities = []
        raw = {}
        errors = []

        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector, headers=self._headers()) as session:
            # Detect target type and query appropriate endpoint
            if target.startswith("http://") or target.startswith("https://"):
                results = await self._scan_url(session, target, errors)
            elif self._is_ip(target):
                results = await self._scan_ip(session, target, errors)
            else:
                results = await self._scan_domain(session, target, errors)

            raw = results

        # Build entities from results
        if raw.get("malicious_count", 0) > 0:
            entities.append(EntityFound(
                entity_type="threat",
                value=f"VirusTotal: {raw.get('malicious_count', 0)} security vendors flagged this as malicious",
                source=self.name, confidence=0.95,
                metadata={
                    "malicious": raw.get("malicious_count", 0),
                    "suspicious": raw.get("suspicious_count", 0),
                    "harmless": raw.get("harmless_count", 0),
                    "undetected": raw.get("undetected_count", 0),
                },
                relationships=[{"type": "FLAGGED_AS", "target": target}],
            ))

        # Extract related domains/IPs
        for item in raw.get("related_domains", []):
            entities.append(EntityFound(
                entity_type="domain", value=item,
                source=self.name, confidence=0.8,
                metadata={"relation": "associated", "parent": target},
                relationships=[{"type": "ASSOCIATED_WITH", "target": target}],
            ))

        for item in raw.get("related_ips", []):
            entities.append(EntityFound(
                entity_type="ip", value=item,
                source=self.name, confidence=0.8,
                metadata={"relation": "resolves_to", "parent": target},
                relationships=[{"type": "RESOLVES_TO", "target": target}],
            ))

        # SSL cert info
        if raw.get("ssl_cert"):
            entities.append(EntityFound(
                entity_type="certificate",
                value=f"SSL: {raw['ssl_cert'].get('issuer', 'Unknown')}",
                source=self.name, confidence=0.9,
                metadata=raw["ssl_cert"],
                relationships=[{"type": "HAS_CERT", "target": target}],
            ))

        # Determine severity
        mal = raw.get("malicious_count", 0)
        sus = raw.get("suspicious_count", 0)
        if mal >= 5:
            severity = "critical"
        elif mal >= 1:
            severity = "high"
        elif sus >= 1:
            severity = "medium"
        else:
            severity = "info"

        reputation = raw.get("reputation", "N/A")
        summary_parts = [
            f"VirusTotal scan for {target}",
            f"Malicious: {mal}",
            f"Suspicious: {sus}",
            f"Reputation: {reputation}",
        ]
        if raw.get("country"):
            summary_parts.append(f"Country: {raw['country']}")
        if raw.get("as_owner"):
            summary_parts.append(f"ASN: {raw['as_owner']}")

        return ScanResult(
            module=self.name, target=target, success=True,
            entities=entities, raw_data=raw,
            summary=" | ".join(summary_parts),
            severity=severity,
        )

    async def _scan_domain(self, session, domain: str, errors: list) -> dict:
        data = {}
        try:
            async with session.get(
                f"{VT_BASE}/domains/{domain}",
                timeout=aiohttp.ClientTimeout(total=20),
            ) as resp:
                if resp.status == 200:
                    j = await resp.json()
                    attrs = j.get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    data["malicious_count"] = stats.get("malicious", 0)
                    data["suspicious_count"] = stats.get("suspicious", 0)
                    data["harmless_count"] = stats.get("harmless", 0)
                    data["undetected_count"] = stats.get("undetected", 0)
                    data["reputation"] = attrs.get("reputation", 0)
                    data["categories"] = attrs.get("categories", {})
                    data["creation_date"] = attrs.get("creation_date")
                    data["last_modification_date"] = attrs.get("last_modification_date")
                    data["registrar"] = attrs.get("registrar")
                    data["whois"] = attrs.get("whois", "")[:500]

                    # SSL
                    cert = attrs.get("last_https_certificate", {})
                    if cert:
                        data["ssl_cert"] = {
                            "issuer": cert.get("issuer", {}).get("O", "Unknown"),
                            "subject": cert.get("subject", {}).get("CN", ""),
                            "validity": cert.get("validity", {}),
                            "serial_number": cert.get("serial_number", ""),
                        }
                elif resp.status == 404:
                    data["note"] = "Domain not found in VirusTotal database"
                else:
                    errors.append(f"VT domain: HTTP {resp.status}")
        except Exception as e:
            errors.append(f"VT domain scan: {str(e)}")

        # Get subdomains
        try:
            async with session.get(
                f"{VT_BASE}/domains/{domain}/subdomains",
                params={"limit": 20},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 200:
                    j = await resp.json()
                    subs = [item.get("id", "") for item in j.get("data", [])]
                    data["related_domains"] = subs
        except Exception:
            pass

        # Get DNS resolutions
        try:
            async with session.get(
                f"{VT_BASE}/domains/{domain}/resolutions",
                params={"limit": 20},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 200:
                    j = await resp.json()
                    ips = []
                    for item in j.get("data", []):
                        attrs = item.get("attributes", {})
                        ip = attrs.get("ip_address", "")
                        if ip:
                            ips.append(ip)
                    data["related_ips"] = ips[:20]
        except Exception:
            pass

        data["errors"] = errors
        return data

    async def _scan_ip(self, session, ip: str, errors: list) -> dict:
        data = {"related_domains": [], "related_ips": []}
        try:
            async with session.get(
                f"{VT_BASE}/ip_addresses/{ip}",
                timeout=aiohttp.ClientTimeout(total=20),
            ) as resp:
                if resp.status == 200:
                    j = await resp.json()
                    attrs = j.get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    data["malicious_count"] = stats.get("malicious", 0)
                    data["suspicious_count"] = stats.get("suspicious", 0)
                    data["harmless_count"] = stats.get("harmless", 0)
                    data["undetected_count"] = stats.get("undetected", 0)
                    data["reputation"] = attrs.get("reputation", 0)
                    data["country"] = attrs.get("country", "")
                    data["as_owner"] = attrs.get("as_owner", "")
                    data["asn"] = attrs.get("asn", 0)
                    data["network"] = attrs.get("network", "")
                    data["continent"] = attrs.get("continent", "")
                else:
                    errors.append(f"VT IP: HTTP {resp.status}")
        except Exception as e:
            errors.append(f"VT IP scan: {str(e)}")

        data["errors"] = errors
        return data

    async def _scan_url(self, session, url: str, errors: list) -> dict:
        data = {"related_domains": [], "related_ips": []}
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        try:
            async with session.get(
                f"{VT_BASE}/urls/{url_id}",
                timeout=aiohttp.ClientTimeout(total=20),
            ) as resp:
                if resp.status == 200:
                    j = await resp.json()
                    attrs = j.get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    data["malicious_count"] = stats.get("malicious", 0)
                    data["suspicious_count"] = stats.get("suspicious", 0)
                    data["harmless_count"] = stats.get("harmless", 0)
                    data["undetected_count"] = stats.get("undetected", 0)
                    data["reputation"] = attrs.get("reputation", 0)
                    data["final_url"] = attrs.get("last_final_url", url)
                    data["title"] = attrs.get("title", "")
                    data["response_code"] = attrs.get("last_http_response_content_length")
                    data["categories"] = attrs.get("categories", {})
                elif resp.status == 404:
                    # Submit URL for scanning
                    try:
                        async with session.post(
                            f"{VT_BASE}/urls",
                            data={"url": url},
                            timeout=aiohttp.ClientTimeout(total=15),
                        ) as submit_resp:
                            if submit_resp.status == 200:
                                data["note"] = "URL submitted for scanning. Results may take a moment."
                    except Exception:
                        pass
                else:
                    errors.append(f"VT URL: HTTP {resp.status}")
        except Exception as e:
            errors.append(f"VT URL scan: {str(e)}")

        data["errors"] = errors
        return data

    @staticmethod
    def _is_ip(target: str) -> bool:
        import re
        return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target))


ModuleRegistry.register(VirusTotalScanner())
