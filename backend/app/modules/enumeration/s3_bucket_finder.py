"""
ShadowNet — Cloud Storage Bucket Finder
Generates plausible AWS S3 / Azure Blob / GCS bucket names derived from the
target's domain & company keyword and probes for public reachability. Open
buckets are flagged as critical findings.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Set
from urllib.parse import urlparse

import aiohttp

from app.modules.base import EntityFound, ModuleRegistry, OSINTModule, ScanResult


SUFFIXES = [
    "", "-backup", "-backups", "-data", "-prod", "-production", "-staging",
    "-dev", "-test", "-uat", "-internal", "-private", "-public", "-assets",
    "-uploads", "-files", "-storage", "-archive", "-logs", "-media",
    "-cdn", "-static", "-images", "-img",
]
PROVIDERS: Dict[str, List[str]] = {
    "aws_s3": [
        "https://{name}.s3.amazonaws.com/",
        "https://{name}.s3-website-us-east-1.amazonaws.com/",
    ],
    "gcs": ["https://storage.googleapis.com/{name}/"],
    "azure_blob": ["https://{name}.blob.core.windows.net/"],
    "digitalocean": ["https://{name}.nyc3.digitaloceanspaces.com/"],
}


class S3BucketFinder(OSINTModule):
    name = "enumeration.s3_buckets"
    description = "Discover public S3 / GCS / Azure / DO Spaces buckets via name fuzzing (free)"
    supported_target_types = ["domain", "url"]
    requires_api_key = False
    rate_limit = 5

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        target = target.strip().lower()
        url = target if target.startswith("http") else f"https://{target}"
        domain = urlparse(url).netloc
        root_label = domain.replace("www.", "").split(".")[0]

        candidates: Set[str] = set()
        for base in {domain.replace(".", "-"), root_label, root_label + "-com", domain}:
            for sfx in SUFFIXES:
                candidates.add(f"{base}{sfx}")

        sem = asyncio.Semaphore(20)
        findings: List[Dict[str, Any]] = []

        async def probe(name: str, provider: str, url_template: str) -> None:
            url = url_template.format(name=name)
            async with sem:
                try:
                    connector = aiohttp.TCPConnector(ssl=False)
                    async with aiohttp.ClientSession(connector=connector) as session:
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8), allow_redirects=False) as resp:
                            text_snippet = ""
                            if resp.status in (200, 403, 301, 302):
                                blob = await resp.read()
                                text_snippet = blob[:300].decode("utf-8", "ignore")
                            outcome = self._classify(provider, resp.status, text_snippet)
                            if outcome:
                                findings.append({
                                    "bucket": name,
                                    "provider": provider,
                                    "url": url,
                                    "status": resp.status,
                                    "state": outcome,
                                    "snippet": text_snippet[:140],
                                })
                except Exception:
                    return

        tasks = []
        for name in candidates:
            for provider, templates in PROVIDERS.items():
                for tpl in templates:
                    tasks.append(probe(name, provider, tpl))
        await asyncio.gather(*tasks)

        entities = []
        for f in findings:
            entities.append(EntityFound(
                entity_type="cloud_bucket", value=f["url"], source=self.name,
                confidence=0.9 if f["state"] == "public" else 0.7,
                metadata={
                    "provider": f["provider"], "bucket": f["bucket"],
                    "status": f["status"], "state": f["state"],
                },
                relationships=[{"type": "ASSOCIATED_WITH", "target": domain}],
            ))

        public_count = sum(1 for f in findings if f["state"] == "public")
        severity = "critical" if public_count else ("medium" if findings else "info")
        summary = (
            f"Cloud buckets for {domain}: {public_count} public, "
            f"{len(findings) - public_count} reachable-but-restricted "
            f"(checked {len(candidates)} candidate names × {sum(len(v) for v in PROVIDERS.values())} providers)"
        )

        return ScanResult(
            module=self.name, target=domain, success=True,
            entities=entities, raw_data={"findings": findings, "candidates_tested": len(candidates)},
            summary=summary, severity=severity,
        )

    @staticmethod
    def _classify(provider: str, status: int, snippet: str) -> str | None:
        snippet_lower = snippet.lower()
        if provider == "aws_s3":
            if status == 200:
                return "public"
            if status == 403 and "accessdenied" in snippet_lower:
                return "exists_private"
            if status == 404 and "nosuchbucket" in snippet_lower:
                return None
        elif provider == "gcs":
            if status == 200:
                return "public"
            if status == 403 and "does not have storage.objects.list access" in snippet_lower:
                return "exists_private"
        elif provider == "azure_blob":
            if status == 200:
                return "public"
            if status == 400 and "invalidqueryparametervalue" not in snippet_lower:
                return "exists_private"
        elif provider == "digitalocean":
            if status == 200:
                return "public"
            if status == 403:
                return "exists_private"
        return None


ModuleRegistry.register(S3BucketFinder())
