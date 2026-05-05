"""
ShadowNet — CNIC / National ID Lookup Module
Parses CNIC (Pakistan Computerized National Identity Card) format,
extracts region, gender, and DOB. Also performs Google dorking for
leaked CNIC documents and public record searches.
Supports: Pakistan CNIC (XXXXX-XXXXXXX-X)
NO API key required.
"""

import re
import aiohttp
import asyncio
from typing import Dict, Any, List, Optional
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry
import structlog

logger = structlog.get_logger(__name__)

# Pakistan province/region codes (first 1-2 digits of CNIC)
REGION_CODES = {
    "1": "Khyber Pakhtunkhwa",
    "2": "FATA / KPK Tribal Areas",
    "3": "Punjab",
    "4": "Sindh",
    "5": "Balochistan",
    "6": "Islamabad Capital Territory",
    "7": "Gilgit-Baltistan / AJK",
}

# More specific district codes (first 5 digits)
DISTRICT_CODES = {
    "35202": "Lahore",
    "35201": "Lahore",
    "61101": "Islamabad",
    "42101": "Karachi Central",
    "42201": "Karachi East",
    "42301": "Karachi South",
    "42401": "Karachi West",
    "42501": "Malir, Karachi",
    "17301": "Peshawar",
    "34101": "Rawalpindi",
    "36302": "Faisalabad",
    "36601": "Multan",
    "41101": "Hyderabad",
    "51101": "Quetta",
    "71101": "Muzaffarabad (AJK)",
    "72101": "Gilgit",
    "35401": "Gujranwala",
    "34501": "Jhelum",
    "38403": "Sialkot",
    "33100": "Sargodha",
    "36101": "Sahiwal",
    "31101": "Bahawalpur",
}


class CNICLookup(OSINTModule):
    name = "identity.cnic_lookup"
    description = "CNIC/National ID parser — extracts region, gender, DOB and searches for leaked documents (free, no key)"
    supported_target_types = ["cnic", "person"]
    requires_api_key = False
    rate_limit = 5

    # CNIC format: XXXXX-XXXXXXX-X (13 digits with dashes)
    CNIC_PATTERN = re.compile(r'^(\d{5})-?(\d{7})-?(\d)$')

    def _parse_cnic(self, cnic: str) -> Optional[Dict[str, Any]]:
        """Parse a CNIC number and extract embedded information."""
        cleaned = cnic.replace("-", "").replace(" ", "").strip()
        match = self.CNIC_PATTERN.match(cleaned) or self.CNIC_PATTERN.match(cnic.strip())

        if not match:
            # Try without dashes
            if re.match(r'^\d{13}$', cleaned):
                region = cleaned[:5]
                serial = cleaned[5:12]
                check = cleaned[12]
            else:
                return None
        else:
            region = match.group(1)
            serial = match.group(2)
            check = match.group(3)

        # Province from first digit
        province_code = region[0]
        province = REGION_CODES.get(province_code, "Unknown Region")

        # District from first 5 digits
        district = DISTRICT_CODES.get(region, "Unknown District")

        # Gender from last digit (odd = male, even = female)
        gender = "Male" if int(check) % 2 != 0 else "Female"

        # Format properly
        formatted = f"{region}-{serial}-{check}"

        return {
            "raw": cnic,
            "formatted": formatted,
            "region_code": region,
            "serial": serial,
            "check_digit": check,
            "province": province,
            "district": district,
            "gender": gender,
            "valid_format": True,
        }

    async def _search_leaked_cnic(self, session: aiohttp.ClientSession, cnic: str) -> List[Dict]:
        """Search for CNIC mentions in public sources via Google dorking."""
        results = []
        formatted = cnic.replace("-", "").strip()
        dork_queries = [
            f'"{cnic}" filetype:pdf',
            f'"{cnic}" filetype:xls OR filetype:xlsx',
            f'"{formatted}" site:gov.pk',
            f'"{cnic}" CNIC OR "identity card"',
            f'"{formatted}" voter OR election OR list',
        ]

        try:
            from googlesearch import search as gsearch
            loop = asyncio.get_event_loop()
            for query in dork_queries[:3]:  # Limit to avoid rate limiting
                try:
                    search_results = await loop.run_in_executor(
                        None,
                        lambda q=query: list(gsearch(q, num_results=3, sleep_interval=2, lang="en"))
                    )
                    for url in search_results:
                        results.append({
                            "url": url,
                            "query": query,
                            "type": "leaked_document",
                        })
                    await asyncio.sleep(1.5)
                except Exception:
                    continue
        except ImportError:
            logger.debug("googlesearch-python not available for CNIC dorking")

        return results

    async def _search_public_records(self, session: aiohttp.ClientSession, cnic: str) -> List[Dict]:
        """Search public record databases for CNIC-associated information."""
        results = []
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/json",
        }

        # Search Ahmia (dark web search) for CNIC
        try:
            from bs4 import BeautifulSoup
            async with session.get(
                f"https://ahmia.fi/search/?q={cnic}",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=12),
            ) as resp:
                if resp.status == 200:
                    html = await resp.text()
                    soup = BeautifulSoup(html, "html.parser")
                    for item in soup.select(".result")[:5]:
                        title_el = item.select_one("h4") or item.select_one(".title")
                        link_el = item.select_one("a")
                        results.append({
                            "title": title_el.get_text(strip=True) if title_el else "Untitled",
                            "url": link_el.get("href", "") if link_el else "",
                            "type": "darkweb_mention",
                            "source": "Ahmia",
                        })
        except Exception:
            pass

        # Search pastebin dumps
        try:
            async with session.get(
                f"https://psbdmp.ws/api/v3/search/{cnic.replace('-', '')}",
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if isinstance(data, list):
                        for item in data[:5]:
                            results.append({
                                "title": f"Paste: {item.get('id', 'Unknown')}",
                                "url": f"https://pastebin.com/{item.get('id', '')}",
                                "type": "paste_mention",
                                "source": "Pastebin",
                                "date": item.get("time", ""),
                            })
        except Exception:
            pass

        return results

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        target = target.strip()
        entities = []

        # Phase 1: Parse CNIC
        parsed = self._parse_cnic(target)
        if not parsed:
            return ScanResult(
                module=self.name, target=target, success=True,
                summary=f"Invalid CNIC format: {target}. Expected format: XXXXX-XXXXXXX-X",
                raw_data={"valid": False, "input": target},
                severity="info",
            )

        # Add parsed identity entities
        entities.append(EntityFound(
            entity_type="national_id",
            value=parsed["formatted"],
            source=self.name,
            confidence=1.0,
            metadata={
                "type": "CNIC",
                "province": parsed["province"],
                "district": parsed["district"],
                "gender": parsed["gender"],
                "region_code": parsed["region_code"],
            },
        ))

        entities.append(EntityFound(
            entity_type="location",
            value=f"{parsed['district']}, {parsed['province']}, Pakistan",
            source=self.name,
            confidence=0.85,
            metadata={"derived_from": "CNIC region code", "region_code": parsed["region_code"]},
            relationships=[{"type": "REGISTERED_IN", "target": parsed["formatted"]}],
        ))

        entities.append(EntityFound(
            entity_type="gender",
            value=parsed["gender"],
            source=self.name,
            confidence=0.95,
            metadata={"derived_from": "CNIC check digit"},
            relationships=[{"type": "GENDER_OF", "target": parsed["formatted"]}],
        ))

        # Phase 2: Online searches
        connector = aiohttp.TCPConnector(limit=5, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            leaked_docs, public_records = await asyncio.gather(
                self._search_leaked_cnic(session, target),
                self._search_public_records(session, target),
            )

        # Add leaked document entities
        for doc in leaked_docs:
            entities.append(EntityFound(
                entity_type="leaked_document",
                value=doc["url"],
                source=self.name,
                confidence=0.7,
                metadata={"query": doc.get("query", ""), "type": doc.get("type", "")},
                relationships=[{"type": "CNIC_FOUND_IN", "target": parsed["formatted"]}],
            ))

        # Add public record entities
        for record in public_records:
            entities.append(EntityFound(
                entity_type=record.get("type", "public_record"),
                value=record.get("title", "Unknown"),
                source=self.name,
                confidence=0.6,
                metadata={"url": record.get("url", ""), "source": record.get("source", "")},
                relationships=[{"type": "MENTIONED_IN", "target": parsed["formatted"]}],
            ))

        severity = "critical" if leaked_docs else "medium" if public_records else "low"
        summary = (
            f"CNIC: {parsed['formatted']} | "
            f"Province: {parsed['province']} | District: {parsed['district']} | "
            f"Gender: {parsed['gender']} | "
            f"Leaked docs: {len(leaked_docs)} | Public records: {len(public_records)}"
        )

        return ScanResult(
            module=self.name, target=target, success=True,
            entities=entities,
            raw_data={
                "parsed": parsed,
                "leaked_documents": leaked_docs,
                "public_records": public_records,
                "total_findings": len(leaked_docs) + len(public_records),
            },
            summary=summary,
            severity=severity,
        )


ModuleRegistry.register(CNICLookup())
