"""
ShadowNet — Wayback Machine Module
Retrieve historical snapshots of a domain from the Internet Archive.
NO API key — uses the free CDX API.
"""

import aiohttp
from typing import Dict, Any
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry


class WaybackMachine(OSINTModule):
    name = "network.wayback_machine"
    description = "Internet Archive Wayback Machine — historical snapshots of websites (free)"
    supported_target_types = ["domain", "url"]
    requires_api_key = False

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        domain = target.strip().lower()
        entities = []
        options = options or {}
        limit = options.get("limit", 50)

        try:
            # CDX API — get snapshot history
            cdx_url = (
                f"http://web.archive.org/cdx/search/cdx?"
                f"url={domain}/*&output=json&fl=timestamp,original,statuscode,mimetype&limit={limit}&collapse=urlkey"
            )
            async with aiohttp.ClientSession() as session:
                async with session.get(cdx_url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status != 200:
                        return ScanResult(
                            module=self.name, target=domain, success=False,
                            error=f"Wayback CDX API returned {resp.status}",
                        )
                    data = await resp.json()

            if not data or len(data) < 2:
                return ScanResult(
                    module=self.name, target=domain, success=True,
                    summary=f"No Wayback Machine snapshots found for {domain}",
                    raw_data={"snapshots": []},
                )

            # First row is headers
            headers = data[0]
            snapshots = []
            unique_urls = set()

            for row in data[1:]:
                snapshot = dict(zip(headers, row))
                snapshots.append(snapshot)
                original_url = snapshot.get("original", "")
                unique_urls.add(original_url)

                # Create entity for discovered URLs
                if original_url and original_url not in unique_urls:
                    entities.append(EntityFound(
                        entity_type="url", value=original_url,
                        source=self.name, confidence=0.8,
                        metadata={
                            "timestamp": snapshot.get("timestamp"),
                            "status_code": snapshot.get("statuscode"),
                            "wayback_url": f"https://web.archive.org/web/{snapshot.get('timestamp')}/{original_url}",
                        },
                        relationships=[{"type": "ARCHIVED_FROM", "target": domain}],
                    ))

            # Get earliest and latest timestamps
            timestamps = [s.get("timestamp", "") for s in snapshots]
            earliest = min(timestamps) if timestamps else "N/A"
            latest = max(timestamps) if timestamps else "N/A"

            summary = (
                f"Wayback Machine: {len(snapshots)} snapshots for {domain} | "
                f"Unique URLs: {len(unique_urls)} | "
                f"Range: {earliest[:4]}-{earliest[4:6]}-{earliest[6:8]} to "
                f"{latest[:4]}-{latest[4:6]}-{latest[6:8]}"
            )

            return ScanResult(
                module=self.name, target=domain, success=True,
                entities=entities,
                raw_data={
                    "total_snapshots": len(snapshots),
                    "unique_urls": len(unique_urls),
                    "earliest": earliest,
                    "latest": latest,
                    "snapshots": snapshots[:20],  # Limit stored data
                },
                summary=summary,
            )

        except Exception as e:
            return ScanResult(
                module=self.name, target=domain, success=False, error=str(e),
            )


ModuleRegistry.register(WaybackMachine())
