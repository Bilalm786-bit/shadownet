"""
ShadowNet — Google Dorking Module
Automated search queries to find exposed data, files, and misconfigurations.
NO API key — constructs dork queries for manual or automated use.
"""

import aiohttp
import urllib.parse
from typing import Dict, Any, List
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry


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
    description = "Generates targeted Google dork queries for OSINT reconnaissance (no API key)"
    supported_target_types = ["domain", "organization", "person", "email"]
    requires_api_key = False

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        target_str = target.strip()
        options = options or {}
        categories = options.get("categories", list(DORK_TEMPLATES.keys()))
        entities = []

        generated_dorks = {}
        total_dorks = 0

        for category in categories:
            templates = DORK_TEMPLATES.get(category, [])
            dorks = []
            for template in templates:
                query = template.format(target=target_str)
                search_url = f"https://www.google.com/search?q={urllib.parse.quote(query)}"
                dorks.append({
                    "query": query,
                    "search_url": search_url,
                    "category": category,
                })
                total_dorks += 1

            generated_dorks[category] = dorks

        # Create entities for each dork category
        for category, dorks in generated_dorks.items():
            entities.append(EntityFound(
                entity_type="dork_query_set",
                value=f"{category}:{target_str}",
                source=self.name,
                confidence=0.5,
                metadata={
                    "category": category,
                    "query_count": len(dorks),
                    "queries": [d["query"] for d in dorks],
                    "search_urls": [d["search_url"] for d in dorks],
                },
            ))

        summary = (
            f"Google Dorking for '{target_str}': Generated {total_dorks} dork queries "
            f"across {len(generated_dorks)} categories: {', '.join(generated_dorks.keys())}"
        )

        return ScanResult(
            module=self.name, target=target_str, success=True,
            entities=entities,
            raw_data={"total_dorks": total_dorks, "categories": generated_dorks},
            summary=summary,
        )


ModuleRegistry.register(GoogleDorker())
