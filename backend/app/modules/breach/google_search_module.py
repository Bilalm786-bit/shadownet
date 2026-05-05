"""
ShadowNet — Google Search Intelligence Module
Uses Google Custom Search API for deep OSINT information gathering.
"""

import aiohttp
import asyncio
import re
from typing import Dict, Any, List
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry
from app.core.config import settings
import structlog

logger = structlog.get_logger(__name__)

PERSON_DORKS = [
    '"{target}" site:linkedin.com',
    '"{target}" site:facebook.com',
    '"{target}" site:github.com',
    '"{target}" email OR contact OR phone',
    '"{target}" breach OR leak OR exposed',
]

DOMAIN_DORKS = [
    'site:{target}',
    'site:{target} inurl:admin OR inurl:login',
    'site:{target} filetype:pdf OR filetype:doc',
    '"{target}" breach OR hack OR leak',
]

EMAIL_DORKS = [
    '"{target}"',
    '"{target}" breach OR leak OR pastebin',
    '"{target}" password OR credentials',
]


class GoogleSearchModule(OSINTModule):
    name = "breach.google_search"
    description = "Google Search intelligence — deep searching for person/domain/email intel"
    supported_target_types = ["email", "username", "domain", "person", "phone"]
    requires_api_key = True
    rate_limit = 10

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        target = target.strip()
        entities, all_results, errors = [], [], []

        if "@" in target:
            dorks = EMAIL_DORKS
        elif re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', target):
            dorks = DOMAIN_DORKS
        else:
            dorks = PERSON_DORKS

        if settings.google_search_api_key:
            all_results = await self._api_search(target, dorks, errors)
        else:
            all_results = await self._library_search(target, dorks, errors)

        for result in all_results:
            url = result.get("link", "")
            title = result.get("title", "")
            snippet = result.get("snippet", "")

            if any(s in url.lower() for s in ["linkedin.com", "facebook.com", "twitter.com", "x.com", "instagram.com", "github.com"]):
                platform = next((p for p in ["LinkedIn", "Facebook", "Twitter", "Instagram", "GitHub"] if p.lower() in url.lower()), "Social")
                entities.append(EntityFound(
                    entity_type="social_profile", value=url,
                    source=self.name, confidence=0.85,
                    metadata={"platform": platform, "title": title},
                    relationships=[{"type": "HAS_PROFILE", "target": target}],
                ))

            if any(kw in (title + snippet).lower() for kw in ["breach", "leak", "exposed", "hack", "pastebin"]):
                entities.append(EntityFound(
                    entity_type="breach_mention", value=title[:100],
                    source=self.name, confidence=0.7,
                    metadata={"url": url, "snippet": snippet[:200]},
                    relationships=[{"type": "MENTIONED_IN", "target": target}],
                ))

            found_emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', snippet)
            for email in found_emails:
                if email.lower() != target.lower():
                    entities.append(EntityFound(
                        entity_type="email", value=email, source=self.name, confidence=0.75,
                        metadata={"found_in": url}, relationships=[{"type": "ASSOCIATED_EMAIL", "target": target}],
                    ))

        breach_count = sum(1 for e in entities if e.entity_type == "breach_mention")
        severity = "critical" if breach_count >= 3 else "high" if breach_count >= 1 else "medium" if len(entities) > 5 else "info"
        summary = f"Google OSINT for {target}: {len(all_results)} results | {len(entities)} entities | {breach_count} breach mentions"

        return ScanResult(
            module=self.name, target=target, success=True, entities=entities,
            raw_data={"total_results": len(all_results), "results": all_results[:20], "errors": errors},
            summary=summary, severity=severity,
        )

    async def _api_search(self, target: str, dorks: list, errors: list) -> list:
        all_results = []
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            for dork in dorks[:5]:
                query = dork.format(target=target)
                try:
                    params = {"key": settings.google_search_api_key, "q": query, "num": 10}
                    if settings.google_search_cx:
                        params["cx"] = settings.google_search_cx
                    async with session.get("https://www.googleapis.com/customsearch/v1", params=params, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            for item in data.get("items", []):
                                all_results.append({"title": item.get("title", ""), "link": item.get("link", ""), "snippet": item.get("snippet", ""), "query": query})
                except Exception as e:
                    errors.append(f"Google API: {str(e)}")
                await asyncio.sleep(0.5)
        return all_results

    async def _library_search(self, target: str, dorks: list, errors: list) -> list:
        all_results = []
        try:
            from googlesearch import search as gsearch
            for dork in dorks[:3]:
                query = dork.format(target=target)
                try:
                    loop = asyncio.get_event_loop()
                    urls = await loop.run_in_executor(None, lambda: list(gsearch(query, num_results=5, sleep_interval=2)))
                    for url in urls:
                        all_results.append({"title": url, "link": url, "snippet": "", "query": query})
                except Exception as e:
                    errors.append(f"Search: {str(e)}")
                await asyncio.sleep(2)
        except ImportError:
            errors.append("googlesearch-python not installed")
        return all_results


ModuleRegistry.register(GoogleSearchModule())
