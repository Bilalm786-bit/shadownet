"""
ShadowNet — Google Dorking Module (v2 — Real Scraping)
Executes dork queries and returns real search results using googlesearch-python.
Falls back to URL generation if scraping is rate-limited.
NO API key required.
"""

import asyncio
import urllib.parse
from typing import Dict, Any, List
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry
import structlog

logger = structlog.get_logger(__name__)

# Try to import googlesearch
try:
    from googlesearch import search as gsearch
    HAS_GOOGLESEARCH = True
except ImportError:
    HAS_GOOGLESEARCH = False
    logger.warning("googlesearch-python not installed — dorking will generate URLs only")


# Predefined dork categories
DORK_TEMPLATES = {
    "exposed_files": [
        'site:{target} filetype:pdf',
        'site:{target} filetype:doc OR filetype:docx',
        'site:{target} filetype:xls OR filetype:xlsx',
        'site:{target} filetype:sql',
        'site:{target} filetype:log',
        'site:{target} filetype:env',
        'site:{target} filetype:bak',
        'site:{target} filetype:conf OR filetype:cfg',
    ],
    "sensitive_pages": [
        'site:{target} inurl:admin',
        'site:{target} inurl:login',
        'site:{target} inurl:dashboard',
        'site:{target} inurl:cpanel',
        'site:{target} inurl:phpmyadmin',
        'site:{target} inurl:wp-admin',
        'site:{target} intitle:"index of /"',
        'site:{target} intitle:"directory listing"',
    ],
    "credentials": [
        'site:{target} intext:"password" filetype:txt',
        'site:{target} intext:"username" filetype:log',
        'site:{target} inurl:".env" intext:"DB_PASSWORD"',
        'site:{target} filetype:sql "INSERT INTO" "password"',
    ],
    "error_messages": [
        'site:{target} intext:"sql syntax" OR "mysql_fetch"',
        'site:{target} intext:"Warning:" filetype:php',
        'site:{target} intext:"Fatal error"',
        'site:{target} intitle:"500 Internal Server Error"',
    ],
    "email_harvest": [
        'site:{target} intext:"@{target}"',
        '"{target}" email OR contact filetype:txt',
        '"{target}" "@" filetype:csv',
    ],
    "social_profiles": [
        'site:linkedin.com "{target}"',
        'site:twitter.com "{target}"',
        'site:github.com "{target}"',
        'site:facebook.com "{target}"',
    ],
    "cloud_storage": [
        'site:amazonaws.com "{target}"',
        'site:blob.core.windows.net "{target}"',
        'site:storage.googleapis.com "{target}"',
        'site:drive.google.com "{target}"',
        'site:pastebin.com "{target}"',
    ],
}


class GoogleDorker(OSINTModule):
    name = "breach.google_dorker"
    description = "Google dorking with real result scraping — finds exposed files, credentials, and misconfigs (no API key)"
    supported_target_types = ["domain", "organization", "person", "email"]
    requires_api_key = False
    rate_limit = 5  # Rate-limited to avoid blocks

    async def _execute_dork(self, query: str, num_results: int = 5) -> List[Dict[str, str]]:
        """Execute a single Google dork query and return real results."""
        results = []
        if not HAS_GOOGLESEARCH:
            return results

        try:
            # Run synchronous googlesearch in executor to avoid blocking
            loop = asyncio.get_event_loop()
            search_results = await loop.run_in_executor(
                None,
                lambda: list(gsearch(query, num_results=num_results, sleep_interval=2, lang="en"))
            )
            for url in search_results:
                results.append({
                    "url": url,
                    "query": query,
                    "scraped": True,
                })
        except Exception as e:
            logger.debug("Google dork execution failed", query=query[:50], error=str(e))

        return results

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        target_str = target.strip()
        options = options or {}
        categories = options.get("categories", list(DORK_TEMPLATES.keys()))
        max_results_per_dork = options.get("max_results", 5)
        scrape_enabled = options.get("scrape", True) and HAS_GOOGLESEARCH
        entities = []

        generated_dorks = {}
        total_dorks = 0
        real_results = []

        for category in categories:
            templates = DORK_TEMPLATES.get(category, [])
            dorks = []
            for template in templates:
                query = template.format(target=target_str)
                search_url = f"https://www.google.com/search?q={urllib.parse.quote(query)}"

                dork_entry = {
                    "query": query,
                    "search_url": search_url,
                    "category": category,
                    "results": [],
                }

                # Actually scrape Google if enabled
                if scrape_enabled:
                    try:
                        scraped = await self._execute_dork(query, max_results_per_dork)
                        dork_entry["results"] = scraped
                        dork_entry["result_count"] = len(scraped)
                        real_results.extend(scraped)
                        # Rate limit between queries
                        await asyncio.sleep(1.5)
                    except Exception as e:
                        dork_entry["error"] = str(e)

                dorks.append(dork_entry)
                total_dorks += 1

            generated_dorks[category] = dorks

        # Create entities for found results
        seen_urls = set()
        for result in real_results:
            url = result.get("url", "")
            if url and url not in seen_urls:
                seen_urls.add(url)
                entities.append(EntityFound(
                    entity_type="exposed_url",
                    value=url,
                    source=self.name,
                    confidence=0.7,
                    metadata={
                        "query": result.get("query", ""),
                        "scraped": result.get("scraped", False),
                    },
                    relationships=[{"type": "DORK_FOUND", "target": target_str}],
                ))

        # Also create category-level entities
        for category, dorks in generated_dorks.items():
            category_results = sum(d.get("result_count", 0) for d in dorks)
            entities.append(EntityFound(
                entity_type="dork_query_set",
                value=f"{category}:{target_str}",
                source=self.name,
                confidence=0.5,
                metadata={
                    "category": category,
                    "query_count": len(dorks),
                    "result_count": category_results,
                    "queries": [d["query"] for d in dorks],
                    "search_urls": [d["search_url"] for d in dorks],
                },
            ))

        scrape_status = "with real results" if scrape_enabled else "URL-only (install googlesearch-python for scraping)"
        summary = (
            f"Google Dorking for '{target_str}': {total_dorks} dork queries "
            f"across {len(generated_dorks)} categories | "
            f"{len(real_results)} real results found ({scrape_status})"
        )

        severity = "high" if len(real_results) > 10 else ("medium" if real_results else "info")

        return ScanResult(
            module=self.name, target=target_str, success=True,
            entities=entities,
            raw_data={
                "total_dorks": total_dorks,
                "categories": generated_dorks,
                "real_results": real_results,
                "real_result_count": len(real_results),
                "scraping_enabled": scrape_enabled,
            },
            summary=summary,
            severity=severity,
        )


ModuleRegistry.register(GoogleDorker())
