"""
ShadowNet — WHOIS Person Lookup Module
Reverse WHOIS — finds domains registered by a person's name or email.
Uses ViewDNS.info and direct WHOIS scraping to discover domain assets.
NO API key required.
"""

import aiohttp
import re
from typing import Dict, Any, List
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry
import structlog

logger = structlog.get_logger(__name__)


class WhoisPersonLookup(OSINTModule):
    name = "identity.whois_person"
    description = "Reverse WHOIS — discovers domains registered by a person's name or email (free, no key)"
    supported_target_types = ["person", "email", "username"]
    requires_api_key = False
    rate_limit = 5

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        target = target.strip()
        entities = []
        domains_found = []
        errors = []

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        connector = aiohttp.TCPConnector(limit=5, ssl=False)

        async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
            # Source 1: ViewDNS.info reverse WHOIS
            viewdns_results = await self._viewdns_reverse_whois(session, target)
            domains_found.extend(viewdns_results)

            # Source 2: WhoisXMLAPI free search
            whoisxml_results = await self._whoisxml_search(session, target)
            domains_found.extend(whoisxml_results)

            # Source 3: Google dork for WHOIS records
            dork_results = await self._google_whois_dork(session, target)
            domains_found.extend(dork_results)

            # Source 4: SecurityTrails (free preview)
            st_results = await self._securitytrails_search(session, target)
            domains_found.extend(st_results)

        # Deduplicate domains
        seen = set()
        unique_domains = []
        for d in domains_found:
            domain = d.get("domain", "").lower()
            if domain and domain not in seen:
                seen.add(domain)
                unique_domains.append(d)

        # Build entities
        for domain_info in unique_domains:
            domain = domain_info["domain"]
            entities.append(EntityFound(
                entity_type="domain",
                value=domain,
                source=self.name,
                confidence=domain_info.get("confidence", 0.7),
                metadata={
                    "registrant": target,
                    "created": domain_info.get("created", ""),
                    "registrar": domain_info.get("registrar", ""),
                    "source": domain_info.get("source", ""),
                },
                relationships=[{"type": "REGISTERED_BY", "target": target}],
            ))

        severity = "high" if len(unique_domains) >= 5 else "medium" if unique_domains else "info"
        summary = (
            f"Reverse WHOIS for '{target}': {len(unique_domains)} domains found | "
            f"Sources: ViewDNS, WhoisXML, Google, SecurityTrails"
        )

        return ScanResult(
            module=self.name, target=target, success=True,
            entities=entities,
            raw_data={
                "domains": unique_domains,
                "domain_count": len(unique_domains),
            },
            summary=summary,
            severity=severity,
        )

    async def _viewdns_reverse_whois(self, session, target: str) -> List[Dict]:
        """ViewDNS.info reverse WHOIS lookup."""
        results = []
        try:
            url = f"https://viewdns.info/reversewhois/?q={target}"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    from bs4 import BeautifulSoup
                    html = await resp.text()
                    soup = BeautifulSoup(html, "html.parser")
                    # Find the results table
                    tables = soup.select("table")
                    for table in tables:
                        rows = table.select("tr")
                        for row in rows[1:]:  # Skip header
                            cells = row.select("td")
                            if len(cells) >= 2:
                                domain = cells[0].get_text(strip=True)
                                created = cells[1].get_text(strip=True) if len(cells) > 1 else ""
                                registrar = cells[2].get_text(strip=True) if len(cells) > 2 else ""
                                if domain and "." in domain and len(domain) > 3:
                                    results.append({
                                        "domain": domain.lower(),
                                        "created": created,
                                        "registrar": registrar,
                                        "source": "ViewDNS",
                                        "confidence": 0.85,
                                    })
        except Exception as e:
            logger.debug("ViewDNS reverse WHOIS failed", error=str(e))
        return results

    async def _whoisxml_search(self, session, target: str) -> List[Dict]:
        """WhoisXMLAPI free reverse WHOIS search preview."""
        results = []
        try:
            url = "https://reverse-whois.whoisxmlapi.com/api/v2"
            # Free tier allows limited searches
            async with session.post(
                url,
                json={"searchType": "current", "mode": "preview",
                      "basicSearchTerms": {"include": [target]}},
                timeout=aiohttp.ClientTimeout(total=12),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for domain in data.get("domainsList", [])[:20]:
                        if isinstance(domain, str):
                            results.append({
                                "domain": domain.lower(),
                                "source": "WhoisXMLAPI",
                                "confidence": 0.8,
                            })
                        elif isinstance(domain, dict):
                            results.append({
                                "domain": domain.get("domainName", "").lower(),
                                "created": domain.get("createdDate", ""),
                                "source": "WhoisXMLAPI",
                                "confidence": 0.8,
                            })
        except Exception as e:
            logger.debug("WhoisXMLAPI search failed", error=str(e))
        return results

    async def _google_whois_dork(self, session, target: str) -> List[Dict]:
        """Google dork for WHOIS records mentioning the target."""
        results = []
        try:
            from googlesearch import search as gsearch
            import asyncio
            loop = asyncio.get_event_loop()
            query = f'"{target}" "registrant" "whois" OR "domain" -site:whois.domaintools.com'
            search_results = await loop.run_in_executor(
                None,
                lambda: list(gsearch(query, num_results=5, sleep_interval=2))
            )
            # Extract domain names from URLs
            for url in search_results:
                domain_match = re.search(r'(?:whois|domain)[^/]*[./]([a-z0-9-]+\.[a-z]{2,})', url, re.I)
                if domain_match:
                    results.append({
                        "domain": domain_match.group(1).lower(),
                        "source": "Google WHOIS Dork",
                        "url": url,
                        "confidence": 0.6,
                    })
        except ImportError:
            pass
        except Exception as e:
            logger.debug("Google WHOIS dork failed", error=str(e))
        return results

    async def _securitytrails_search(self, session, target: str) -> List[Dict]:
        """SecurityTrails free domain search."""
        results = []
        try:
            # SecurityTrails has a free autocomplete endpoint
            async with session.get(
                f"https://securitytrails.com/app/sb/search?query={target}",
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "application/json",
                    "Referer": "https://securitytrails.com/",
                },
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for item in data.get("result", data.get("records", []))[:10]:
                        domain = item.get("hostname", item.get("domain", ""))
                        if domain and "." in domain:
                            results.append({
                                "domain": domain.lower(),
                                "source": "SecurityTrails",
                                "confidence": 0.75,
                            })
        except Exception as e:
            logger.debug("SecurityTrails search failed", error=str(e))
        return results


ModuleRegistry.register(WhoisPersonLookup())
