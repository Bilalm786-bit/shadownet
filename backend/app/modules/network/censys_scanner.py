"""
ShadowNet — Censys Scanner Module
Uses Censys search API for host/certificate discovery and web scraping fallback.
"""

import aiohttp
import base64
from typing import Dict, Any
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry
from app.core.config import settings
import structlog

logger = structlog.get_logger(__name__)
CENSYS_API = "https://search.censys.io/api"


class CensysScanner(OSINTModule):
    name = "network.censys"
    description = "Censys.io — host discovery, certificate transparency, open port enumeration"
    supported_target_types = ["domain", "ip"]
    requires_api_key = True
    rate_limit = 5

    def _auth_header(self):
        if settings.censys_api_id and settings.censys_api_secret:
            creds = base64.b64encode(f"{settings.censys_api_id}:{settings.censys_api_secret}".encode()).decode()
            return {"Authorization": f"Basic {creds}", "Accept": "application/json"}
        return None

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        target = target.strip()
        entities, errors = [], []
        raw = {"hosts": [], "certificates": [], "services": []}

        auth = self._auth_header()
        if auth:
            raw = await self._api_search(target, auth, errors)
        else:
            raw = await self._scrape_search(target, errors)

        for host in raw.get("hosts", []):
            ip = host.get("ip", "")
            if ip:
                entities.append(EntityFound(
                    entity_type="ip", value=ip, source=self.name, confidence=0.9,
                    metadata={"services": host.get("services", []), "os": host.get("os", ""), "location": host.get("location", {})},
                    relationships=[{"type": "HOSTS", "target": target}],
                ))
            for svc in host.get("services", []):
                entities.append(EntityFound(
                    entity_type="service", value=f"{svc.get('service_name', 'unknown')}:{svc.get('port', '?')}",
                    source=self.name, confidence=0.85,
                    metadata={"port": svc.get("port"), "protocol": svc.get("transport_protocol", ""), "banner": svc.get("banner", "")[:200]},
                    relationships=[{"type": "RUNS_SERVICE", "target": ip or target}],
                ))

        for cert in raw.get("certificates", []):
            entities.append(EntityFound(
                entity_type="certificate", value=cert.get("subject", "Unknown cert"),
                source=self.name, confidence=0.9,
                metadata=cert,
                relationships=[{"type": "HAS_CERT", "target": target}],
            ))

        svc_count = sum(len(h.get("services", [])) for h in raw.get("hosts", []))
        severity = "high" if svc_count > 10 else "medium" if svc_count > 3 else "info"
        summary = f"Censys scan for {target}: {len(raw.get('hosts', []))} hosts | {svc_count} services | {len(raw.get('certificates', []))} certs"

        return ScanResult(
            module=self.name, target=target, success=True, entities=entities,
            raw_data=raw, summary=summary, severity=severity,
        )

    async def _api_search(self, target: str, auth: dict, errors: list) -> dict:
        raw = {"hosts": [], "certificates": [], "services": []}
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector, headers=auth) as session:
            try:
                async with session.get(f"{CENSYS_API}/v2/hosts/search", params={"q": target, "per_page": 25}, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for hit in data.get("result", {}).get("hits", []):
                            raw["hosts"].append({
                                "ip": hit.get("ip", ""),
                                "services": [{"port": s.get("port"), "service_name": s.get("service_name", ""), "transport_protocol": s.get("transport_protocol", "")} for s in hit.get("services", [])],
                                "os": hit.get("operating_system", {}).get("product", ""),
                                "location": hit.get("location", {}),
                            })
                    else:
                        errors.append(f"Censys hosts: HTTP {resp.status}")
            except Exception as e:
                errors.append(f"Censys API: {str(e)}")

            try:
                async with session.get(f"{CENSYS_API}/v2/certificates/search", params={"q": target, "per_page": 10}, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for hit in data.get("result", {}).get("hits", []):
                            names = hit.get("names", [])
                            raw["certificates"].append({"subject": ", ".join(names[:3]) if names else "Unknown", "fingerprint": hit.get("fingerprint_sha256", ""), "issuer": hit.get("parsed", {}).get("issuer_dn", "")})
            except Exception as e:
                errors.append(f"Censys certs: {str(e)}")

        raw["errors"] = errors
        return raw

    async def _scrape_search(self, target: str, errors: list) -> dict:
        """Fallback: scrape Censys search page."""
        raw = {"hosts": [], "certificates": [], "services": [], "note": "Using web scraping (no API keys)"}
        try:
            from bs4 import BeautifulSoup
            connector = aiohttp.TCPConnector(ssl=False)
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
                async with session.get(f"https://search.censys.io/hosts/{target}", timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        html = await resp.text()
                        soup = BeautifulSoup(html, "html.parser")
                        services = []
                        for row in soup.select("table tr"):
                            cols = row.find_all("td")
                            if len(cols) >= 2:
                                services.append({"port": cols[0].get_text(strip=True), "service_name": cols[1].get_text(strip=True)})
                        if services:
                            raw["hosts"].append({"ip": target, "services": services})
        except Exception as e:
            errors.append(f"Censys scrape: {str(e)}")
        raw["errors"] = errors
        return raw


ModuleRegistry.register(CensysScanner())
