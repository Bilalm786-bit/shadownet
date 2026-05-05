"""
ShadowNet — Tavily AI Search Module
Uses Tavily API for AI-powered deep web search with structured results.
"""

import aiohttp
from typing import Dict, Any
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry
from app.core.config import settings
import structlog, re

logger = structlog.get_logger(__name__)


class TavilySearch(OSINTModule):
    name = "breach.tavily_search"
    description = "Tavily AI-powered search — deep web intelligence gathering with structured results"
    supported_target_types = ["email", "username", "domain", "person", "phone", "ip", "url"]
    requires_api_key = True
    rate_limit = 5

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        target = target.strip()
        if not settings.tavily_api_key:
            return ScanResult(module=self.name, target=target, success=False, error="Tavily API key not configured")

        entities, errors = [], []
        queries = self._build_queries(target)
        all_results = []

        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            for query in queries[:3]:
                try:
                    payload = {
                        "api_key": settings.tavily_api_key,
                        "query": query,
                        "search_depth": "advanced",
                        "include_answer": True,
                        "include_raw_content": False,
                        "max_results": 10,
                    }
                    async with session.post(
                        "https://api.tavily.com/search",
                        json=payload,
                        timeout=aiohttp.ClientTimeout(total=30),
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            ai_answer = data.get("answer", "")
                            results = data.get("results", [])
                            for r in results:
                                all_results.append({
                                    "title": r.get("title", ""),
                                    "url": r.get("url", ""),
                                    "content": r.get("content", "")[:500],
                                    "score": r.get("score", 0),
                                    "query": query,
                                })
                            if ai_answer:
                                all_results.append({"title": "AI Summary", "url": "", "content": ai_answer, "score": 1.0, "query": query})
                        else:
                            errors.append(f"Tavily HTTP {resp.status}")
                except Exception as e:
                    errors.append(f"Tavily: {str(e)}")

        # Extract entities
        for r in all_results:
            content = r.get("content", "") + " " + r.get("title", "")
            url = r.get("url", "")

            if any(kw in content.lower() for kw in ["breach", "leak", "exposed", "hack", "credential"]):
                entities.append(EntityFound(
                    entity_type="breach_mention", value=r.get("title", "")[:100],
                    source=self.name, confidence=r.get("score", 0.7),
                    metadata={"url": url, "content": r.get("content", "")[:300]},
                    relationships=[{"type": "MENTIONED_IN", "target": target}],
                ))

            found_emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', content)
            for email in found_emails:
                if email.lower() != target.lower():
                    entities.append(EntityFound(
                        entity_type="email", value=email, source=self.name, confidence=0.7,
                        metadata={"found_in": url}, relationships=[{"type": "DISCOVERED", "target": target}],
                    ))

            if any(s in url.lower() for s in ["linkedin", "facebook", "twitter", "github", "instagram"]):
                entities.append(EntityFound(
                    entity_type="social_profile", value=url,
                    source=self.name, confidence=0.8,
                    metadata={"title": r.get("title", "")},
                    relationships=[{"type": "HAS_PROFILE", "target": target}],
                ))

        breach_count = sum(1 for e in entities if e.entity_type == "breach_mention")
        severity = "critical" if breach_count >= 3 else "high" if breach_count >= 1 else "info"
        summary = f"Tavily deep search for {target}: {len(all_results)} results | {len(entities)} entities | {breach_count} breach mentions"

        return ScanResult(
            module=self.name, target=target, success=True, entities=entities,
            raw_data={"total_results": len(all_results), "results": all_results[:15], "errors": errors},
            summary=summary, severity=severity,
        )

    def _build_queries(self, target: str) -> list:
        if "@" in target:
            return [f"{target} data breach leak", f"{target} social media profiles", f"{target} dark web exposed"]
        elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
            return [f"IP {target} threat intelligence", f"{target} malware reputation abuse"]
        elif re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', target):
            return [f"{target} security vulnerabilities", f"{target} data breach history", f"site:{target} exposed data"]
        else:
            return [f'"{target}" personal information OSINT', f'"{target}" breach leak exposed', f'"{target}" social media profiles']


ModuleRegistry.register(TavilySearch())
