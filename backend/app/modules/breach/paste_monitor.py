"""
ShadowNet — Paste Site Monitor
Scrapes public paste sites for mentions of target email/domain/username.
Sources: PasteBin public archive, Rentry, dpaste, etc.
NO API key required.
"""

import aiohttp
import asyncio
import re
from typing import Dict, Any, List
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry
import structlog

logger = structlog.get_logger(__name__)


class PasteMonitor(OSINTModule):
    name = "breach.paste_monitor"
    description = "Scrapes paste sites (PasteBin, dpaste, etc.) for target mentions — leaked data detection (free, no key)"
    supported_target_types = ["email", "domain", "username"]
    requires_api_key = False
    rate_limit = 5

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        target = target.strip().lower()
        entities = []
        pastes_found = []
        sources_checked = []
        errors = []

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/json",
        }
        connector = aiohttp.TCPConnector(limit=5, ssl=False)

        async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
            # Check multiple paste/leak sources
            tasks = {
                "google_cache": self._search_google_cache(session, target),
                "ahmia_search": self._search_ahmia(session, target),
                "intelx_preview": self._search_intelx_preview(session, target),
                "psbdmp": self._search_psbdmp(session, target),
            }

            keys = list(tasks.keys())
            results = await asyncio.gather(*tasks.values(), return_exceptions=True)

            for name, result in zip(keys, results):
                if isinstance(result, Exception):
                    errors.append(f"{name}: {str(result)}")
                elif result:
                    pastes_found.extend(result)
                    sources_checked.append(name)

        # Deduplicate
        seen = set()
        unique_pastes = []
        for paste in pastes_found:
            key = paste.get("url", "") or paste.get("id", "")
            if key and key not in seen:
                seen.add(key)
                unique_pastes.append(paste)

        # Build entities
        for paste in unique_pastes:
            entities.append(EntityFound(
                entity_type="paste",
                value=paste.get("url", paste.get("title", "Unknown paste")),
                source=self.name,
                confidence=paste.get("confidence", 0.7),
                metadata={
                    "title": paste.get("title", ""),
                    "date": paste.get("date", ""),
                    "source": paste.get("source", ""),
                    "snippet": paste.get("snippet", "")[:300],
                },
                relationships=[{"type": "MENTIONED_IN", "target": target}],
            ))

        summary_parts = [
            f"Paste monitor for '{target}'",
            f"Sources checked: {len(sources_checked)}",
            f"Pastes found: {len(unique_pastes)}",
        ]
        if errors:
            summary_parts.append(f"Errors: {len(errors)}")

        severity = "high" if len(unique_pastes) > 5 else ("medium" if unique_pastes else "info")

        return ScanResult(
            module=self.name, target=target, success=True,
            entities=entities,
            raw_data={
                "pastes": unique_pastes,
                "total_found": len(unique_pastes),
                "sources_checked": sources_checked,
                "errors": errors,
            },
            summary=" | ".join(summary_parts),
            severity=severity,
        )

    async def _search_google_cache(self, session: aiohttp.ClientSession, target: str) -> List[Dict]:
        """Search Google cache for paste site mentions."""
        pastes = []
        queries = [
            f"site:pastebin.com \"{target}\"",
            f"site:dpaste.org \"{target}\"",
            f"site:ghostbin.co \"{target}\"",
        ]
        # We use google search hints — actual execution requires googlesearch-python
        try:
            from googlesearch import search as gsearch
            for query in queries:
                loop = asyncio.get_event_loop()
                results = await loop.run_in_executor(
                    None, lambda q=query: list(gsearch(q, num_results=3, sleep_interval=2))
                )
                for url in results:
                    pastes.append({
                        "url": url,
                        "title": f"Paste mention of {target}",
                        "source": "google_cache",
                        "confidence": 0.75,
                    })
                await asyncio.sleep(2)
        except ImportError:
            pass
        except Exception as e:
            logger.debug("Google cache search failed", error=str(e))
        return pastes

    async def _search_ahmia(self, session: aiohttp.ClientSession, target: str) -> List[Dict]:
        """Search Ahmia.fi (clearnet Tor search engine) for mentions."""
        pastes = []
        try:
            url = f"https://ahmia.fi/search/?q={target}"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    body = await resp.text(errors="ignore")
                    # Extract search results
                    results = re.findall(
                        r'<li class="result">\s*<h4><a href="([^"]+)"[^>]*>([^<]+)</a></h4>\s*<p>([^<]*)</p>',
                        body, re.I
                    )
                    for link, title, snippet in results[:10]:
                        if target.lower() in (title + snippet).lower():
                            pastes.append({
                                "url": link,
                                "title": title.strip(),
                                "snippet": snippet.strip()[:200],
                                "source": "ahmia",
                                "confidence": 0.6,
                            })
        except Exception as e:
            logger.debug("Ahmia search failed", error=str(e))
        return pastes

    async def _search_intelx_preview(self, session: aiohttp.ClientSession, target: str) -> List[Dict]:
        """Search IntelX free preview for mentions."""
        pastes = []
        try:
            url = f"https://2.intelx.io/phonebook/search?term={target}&maxresults=5&media=0&target=1"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for item in data.get("selectors", [])[:5]:
                        pastes.append({
                            "url": f"https://intelx.io/?s={target}",
                            "title": item.get("selectorvalue", ""),
                            "source": "intelx",
                            "date": item.get("lastseentime", ""),
                            "confidence": 0.65,
                        })
        except Exception:
            pass
        return pastes

    async def _search_psbdmp(self, session: aiohttp.ClientSession, target: str) -> List[Dict]:
        """Search psbdmp.ws (PasteBin dump search)."""
        pastes = []
        try:
            url = f"https://psbdmp.ws/api/v3/search/{target}"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for item in data.get("data", [])[:10]:
                        paste_id = item.get("id", "")
                        pastes.append({
                            "url": f"https://pastebin.com/{paste_id}" if paste_id else "",
                            "id": paste_id,
                            "title": item.get("tags", "Untitled"),
                            "date": item.get("time", ""),
                            "source": "psbdmp",
                            "confidence": 0.8,
                        })
        except Exception as e:
            logger.debug("PSBDMP search failed", error=str(e))
        return pastes


ModuleRegistry.register(PasteMonitor())
