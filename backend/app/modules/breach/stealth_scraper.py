"""
ShadowNet — Stealth Scraper Module
Uses stealth browser endpoint + direct scraping for dark web paste sites,
forums, and breach databases that don't have APIs.
"""

import aiohttp
import asyncio
import re
from typing import Dict, Any, List
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry
from app.core.config import settings
import structlog

logger = structlog.get_logger(__name__)

PASTE_SITES = [
    {"name": "Pastebin", "search_url": "https://psbdmp.ws/api/v3/search/{target}", "type": "api"},
    {"name": "IntelX", "search_url": "https://2.intelx.io/phonebook/search", "type": "api"},
]

DARKWEB_SEARCH_ENGINES = [
    {"name": "Ahmia", "url": "https://ahmia.fi/search/?q={target}"},
    {"name": "DarkSearch", "url": "https://darksearch.io/api/search?query={target}"},
]

OSINT_AGGREGATORS = [
    {"name": "Hunter.io", "url": "https://api.hunter.io/v2/email-finder?domain={target}&api_key=free"},
    {"name": "Dehashed Preview", "url": "https://api.dehashed.com/search?query={target}"},
]


class StealthScraper(OSINTModule):
    name = "breach.stealth_scraper"
    description = "Stealth scraping — dark web paste sites, breach forums, and deep web search engines"
    supported_target_types = ["email", "username", "domain", "person", "phone"]
    requires_api_key = False
    rate_limit = 3

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        target = target.strip()
        entities, errors = [], []
        all_results = []

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/json",
        }
        connector = aiohttp.TCPConnector(ssl=False, limit=5)

        async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
            tasks = [
                self._search_paste_dumps(session, target),
                self._search_ahmia(session, target),
                self._search_darksearch(session, target),
                self._search_intelx_preview(session, target),
                self._search_leak_lookup(session, target),
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    errors.append(str(result))
                elif result:
                    all_results.extend(result)

        # Build entities from results
        for item in all_results:
            source_name = item.get("source", "unknown")
            if item.get("type") == "paste":
                entities.append(EntityFound(
                    entity_type="paste", value=f"{source_name}: {item.get('title', 'Untitled')[:80]}",
                    source=self.name, confidence=item.get("confidence", 0.7),
                    metadata={"url": item.get("url", ""), "date": item.get("date", ""), "content_preview": item.get("content", "")[:300]},
                    relationships=[{"type": "FOUND_IN_PASTE", "target": target}],
                ))
            elif item.get("type") == "darkweb":
                entities.append(EntityFound(
                    entity_type="darkweb_mention", value=item.get("title", "Dark web mention")[:100],
                    source=self.name, confidence=0.6,
                    metadata={"url": item.get("url", ""), "source": source_name, "snippet": item.get("content", "")[:300]},
                    relationships=[{"type": "DARKWEB_MENTION", "target": target}],
                ))
            elif item.get("type") == "breach_data":
                entities.append(EntityFound(
                    entity_type="breach", value=f"Breach: {item.get('title', 'Unknown')}",
                    source=self.name, confidence=0.75,
                    metadata=item,
                    relationships=[{"type": "BREACHED_IN", "target": target}],
                ))

        paste_count = sum(1 for e in entities if e.entity_type == "paste")
        dw_count = sum(1 for e in entities if e.entity_type == "darkweb_mention")
        breach_count = sum(1 for e in entities if e.entity_type == "breach")

        severity = "critical" if breach_count > 0 or paste_count > 3 else "high" if dw_count > 0 or paste_count > 0 else "info"
        summary = f"Stealth scan for {target}: {paste_count} pastes | {dw_count} dark web mentions | {breach_count} breach records"

        return ScanResult(
            module=self.name, target=target, success=True, entities=entities,
            raw_data={"results": all_results[:30], "total": len(all_results), "errors": errors},
            summary=summary, severity=severity,
        )

    async def _search_paste_dumps(self, session, target: str) -> List[Dict]:
        results = []
        try:
            async with session.get(f"https://psbdmp.ws/api/v3/search/{target}", timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if isinstance(data, list):
                        for item in data[:10]:
                            results.append({"type": "paste", "source": "Pastebin Dump", "title": item.get("id", ""), "url": f"https://pastebin.com/{item.get('id', '')}", "date": item.get("time", ""), "content": item.get("text", "")[:500], "confidence": 0.8})
        except Exception:
            pass
        return results

    async def _search_ahmia(self, session, target: str) -> List[Dict]:
        results = []
        try:
            from bs4 import BeautifulSoup
            async with session.get(f"https://ahmia.fi/search/?q={target}", timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    html = await resp.text()
                    soup = BeautifulSoup(html, "html.parser")
                    for item in soup.select(".result")[:10]:
                        title_el = item.select_one("h4") or item.select_one(".title")
                        link_el = item.select_one("a")
                        desc_el = item.select_one("p") or item.select_one(".description")
                        results.append({"type": "darkweb", "source": "Ahmia", "title": title_el.get_text(strip=True) if title_el else "Untitled", "url": link_el.get("href", "") if link_el else "", "content": desc_el.get_text(strip=True) if desc_el else ""})
        except Exception:
            pass
        return results

    async def _search_darksearch(self, session, target: str) -> List[Dict]:
        results = []
        try:
            async with session.get(f"https://darksearch.io/api/search?query={target}&page=1", timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for item in data.get("data", [])[:10]:
                        results.append({"type": "darkweb", "source": "DarkSearch", "title": item.get("title", ""), "url": item.get("link", ""), "content": item.get("description", "")[:300]})
        except Exception:
            pass
        return results

    async def _search_intelx_preview(self, session, target: str) -> List[Dict]:
        results = []
        try:
            async with session.post(
                "https://2.intelx.io/phonebook/search",
                json={"term": target, "maxresults": 10, "media": 0, "target": 1},
                headers={"x-key": "9df61df0-84f7-4dc7-b34c-8ccfb8646ee9"},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    search_id = data.get("id")
                    if search_id:
                        await asyncio.sleep(2)
                        async with session.get(f"https://2.intelx.io/phonebook/search/result?id={search_id}&limit=10", headers={"x-key": "9df61df0-84f7-4dc7-b34c-8ccfb8646ee9"}, timeout=aiohttp.ClientTimeout(total=10)) as resp2:
                            if resp2.status == 200:
                                data2 = await resp2.json()
                                for sel in data2.get("selectors", [])[:10]:
                                    results.append({"type": "breach_data", "source": "IntelX", "title": sel.get("selectorvalue", ""), "content": f"Type: {sel.get('selectortypeh', '')}"})
        except Exception:
            pass
        return results

    async def _search_leak_lookup(self, session, target: str) -> List[Dict]:
        results = []
        try:
            async with session.get(f"https://leak-lookup.com/api/search", params={"key": "free", "type": "email_address" if "@" in target else "username", "query": target}, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("error") == "false" and data.get("message"):
                        for db_name, entries in (data.get("message", {}) if isinstance(data.get("message"), dict) else {}).items():
                            results.append({"type": "breach_data", "source": f"LeakLookup:{db_name}", "title": db_name, "content": str(entries)[:300], "confidence": 0.8})
        except Exception:
            pass
        return results


ModuleRegistry.register(StealthScraper())
