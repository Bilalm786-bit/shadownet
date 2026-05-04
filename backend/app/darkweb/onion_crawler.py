"""
ShadowNet — Dark Web: Onion Crawler
Searches dark web search engines via clearnet interfaces (no Tor required).
Multi-source: Ahmia.fi (primary), with resilient HTML parsing and fallback selectors.
"""

import aiohttp
from bs4 import BeautifulSoup
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry
from typing import Dict, Any, List
import re
import structlog

logger = structlog.get_logger(__name__)

AHMIA_SEARCH_URL = "https://ahmia.fi/search/"

# Multiple CSS selector strategies for resilient parsing
AHMIA_SELECTORS = [
    # Current Ahmia layout (2024-2026)
    {"container": "li.result", "title": "h4", "link": "a", "desc": "p", "cite": "cite"},
    # Alternate layout
    {"container": ".result", "title": "h4", "link": "a[href]", "desc": ".result-description", "cite": "cite"},
    # Fallback: generic search result patterns
    {"container": ".search-result", "title": "h3", "link": "a", "desc": "p", "cite": ".url"},
    # Last resort: grab all links with onion references
    {"container": "li", "title": "h4,h3,h2", "link": "a[href]", "desc": "p,span", "cite": "cite,code"},
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
]


def _extract_onion_urls(text: str) -> List[str]:
    """Extract .onion URLs from raw text."""
    pattern = r'https?://[a-z2-7]{16,56}\.onion[^\s"\'<>]*'
    return list(set(re.findall(pattern, text, re.IGNORECASE)))


def _parse_ahmia_results(html: str, limit: int = 20) -> List[Dict]:
    """Parse Ahmia search results with multiple fallback selector strategies."""
    soup = BeautifulSoup(html, "html.parser")
    results = []

    for selectors in AHMIA_SELECTORS:
        items = soup.select(selectors["container"])[:limit]
        if not items:
            continue

        for item in items:
            # Title
            title_el = item.select_one(selectors["title"])
            title = title_el.get_text(strip=True) if title_el else ""

            # URL — prefer cite element (shows actual .onion), fallback to href
            cite_el = item.select_one(selectors["cite"]) if selectors.get("cite") else None
            link_el = item.select_one(selectors["link"])

            url = ""
            if cite_el:
                url = cite_el.get_text(strip=True)
            elif link_el:
                href = link_el.get("href", "")
                # Ahmia wraps URLs in redirect: /search/redirect?search_url=...
                if "redirect" in href and "search_url=" in href:
                    import urllib.parse
                    parsed = urllib.parse.parse_qs(urllib.parse.urlparse(href).query)
                    url = parsed.get("search_url", [href])[0]
                else:
                    url = href

            # Description
            desc_el = item.select_one(selectors["desc"])
            description = desc_el.get_text(strip=True) if desc_el else ""

            # Skip empty/useless results
            if not title and not url:
                continue

            results.append({
                "title": title or "Untitled",
                "url": url,
                "description": description[:500],
                "source": "ahmia.fi",
                "type": "onion_result",
                "is_onion": ".onion" in url.lower(),
            })

        # If we found results with this selector strategy, stop trying others
        if results:
            break

    # Also extract any raw .onion URLs from the entire page as bonus
    raw_onions = _extract_onion_urls(html)
    existing_urls = {r["url"] for r in results}
    for onion_url in raw_onions[:5]:
        if onion_url not in existing_urls:
            results.append({
                "title": f"Hidden Service: {onion_url[:40]}...",
                "url": onion_url,
                "description": "Onion address found in search results",
                "source": "ahmia.fi",
                "type": "onion_result",
                "is_onion": True,
            })

    return results


class OnionCrawler(OSINTModule):
    name = "darkweb.onion_search"
    description = "Search dark web via Ahmia.fi clearnet gateway with resilient parsing"
    supported_target_types = ["domain", "email", "username", "person", "organization", "keyword"]
    requires_api_key = False

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        entities = []
        raw_data = {"results": [], "source": "ahmia.fi", "parser_strategy": "unknown"}

        try:
            headers = {"User-Agent": USER_AGENTS[0], "Accept": "text/html,application/xhtml+xml"}
            async with aiohttp.ClientSession() as session:
                params = {"q": target}
                async with session.get(
                    AHMIA_SEARCH_URL, params=params, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                    ssl=False, allow_redirects=True,
                ) as resp:
                    if resp.status == 200:
                        html = await resp.text()
                        results = _parse_ahmia_results(html, limit=20)

                        for r in results:
                            if r.get("is_onion"):
                                entities.append(EntityFound(
                                    entity_type="onion_url",
                                    value=r["url"],
                                    source=self.name,
                                    confidence=0.75,
                                    metadata={
                                        "title": r["title"],
                                        "description": r["description"],
                                    },
                                    relationships=[{
                                        "type": "FOUND_ON_DARKWEB",
                                        "target": target,
                                    }],
                                ))

                        raw_data["results"] = results
                        raw_data["total_found"] = len(results)
                        raw_data["onion_count"] = sum(1 for r in results if r.get("is_onion"))
                    else:
                        raw_data["http_status"] = resp.status
                        raw_data["error"] = f"Ahmia returned HTTP {resp.status}"

            severity = "high" if len(entities) > 5 else "medium" if entities else "info"
            summary = f"Found {len(entities)} dark web mentions for '{target}' via Ahmia.fi ({len(raw_data.get('results', []))} total results)"

            return ScanResult(
                module=self.name, target=target, success=True,
                entities=entities, raw_data=raw_data,
                summary=summary, severity=severity,
            )
        except Exception as e:
            logger.error("Onion crawler failed", error=str(e), target=target)
            return ScanResult(
                module=self.name, target=target, success=False,
                error=str(e), summary=f"Dark web search failed: {str(e)}",
            )


# Auto-register
_module = OnionCrawler()
ModuleRegistry.register(_module)
