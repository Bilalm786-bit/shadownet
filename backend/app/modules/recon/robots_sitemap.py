"""
ShadowNet — Robots.txt + Sitemap Analyzer
Extracts disallowed paths, sitemap references, and crawls XML sitemaps to enumerate
URLs the site owner does not want indexed (often a goldmine for hidden endpoints).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree as ET

import aiohttp

from app.modules.base import EntityFound, ModuleRegistry, OSINTModule, ScanResult


class RobotsSitemapAnalyzer(OSINTModule):
    name = "recon.robots_sitemap"
    description = "Parse robots.txt + sitemap.xml to surface hidden/disallowed paths (free)"
    supported_target_types = ["domain", "url"]
    requires_api_key = False

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        target = target.strip().lower()
        url_base = target if target.startswith("http") else f"https://{target}"
        domain = urlparse(url_base).netloc

        data: Dict[str, Any] = {
            "robots_url": urljoin(url_base, "/robots.txt"),
            "user_agents": [],
            "disallowed": [],
            "allowed": [],
            "sitemaps": [],
            "sitemap_urls": [],
        }

        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            try:
                async with session.get(data["robots_url"], timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="ignore")
                        data["robots_status"] = resp.status
                        data["robots_size"] = len(text)
                        self._parse_robots(text, data)
                    else:
                        data["robots_status"] = resp.status
            except Exception as exc:
                data["robots_error"] = str(exc)

            if not data["sitemaps"]:
                for guess in ("/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml"):
                    candidate = urljoin(url_base, guess)
                    try:
                        async with session.head(candidate, timeout=aiohttp.ClientTimeout(total=8), allow_redirects=True) as resp:
                            if resp.status == 200:
                                data["sitemaps"].append(candidate)
                    except Exception:
                        pass

            for sm in list(data["sitemaps"])[:5]:
                await self._fetch_sitemap(session, sm, data, depth=0)

        urls = sorted(set(data["sitemap_urls"]))[:500]
        data["sitemap_urls"] = urls
        data["sitemap_url_count"] = len(urls)

        entities: List[EntityFound] = []
        for path in data["disallowed"][:100]:
            entities.append(EntityFound(
                entity_type="hidden_path", value=urljoin(url_base, path),
                source=self.name, confidence=0.9,
                metadata={"declared_in": "robots.txt", "directive": "Disallow"},
                relationships=[{"type": "DISALLOWS", "target": domain}],
            ))
        for sm in data["sitemaps"]:
            entities.append(EntityFound(
                entity_type="sitemap", value=sm, source=self.name, confidence=1.0,
                metadata={"domain": domain},
                relationships=[{"type": "DESCRIBES", "target": domain}],
            ))

        severity = "medium" if len(data["disallowed"]) > 5 else "info"
        summary = (
            f"robots+sitemap on {domain}: "
            f"{len(data['disallowed'])} disallowed paths, "
            f"{len(data['sitemaps'])} sitemaps, "
            f"{len(urls)} sitemap URLs"
        )

        return ScanResult(
            module=self.name, target=domain, success=True,
            entities=entities, raw_data=data, summary=summary, severity=severity,
        )

    @staticmethod
    def _parse_robots(text: str, data: Dict[str, Any]) -> None:
        current_ua = "*"
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line or ":" not in line:
                continue
            directive, _, value = (s.strip() for s in line.partition(":"))
            d = directive.lower()
            if d == "user-agent":
                current_ua = value
                if value not in data["user_agents"]:
                    data["user_agents"].append(value)
            elif d == "disallow" and value:
                data["disallowed"].append(value)
            elif d == "allow" and value:
                data["allowed"].append(value)
            elif d == "sitemap" and value:
                data["sitemaps"].append(value)

    async def _fetch_sitemap(self, session: aiohttp.ClientSession, url: str, data: Dict[str, Any], depth: int) -> None:
        if depth > 2 or len(data["sitemap_urls"]) >= 500:
            return
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    return
                blob = await resp.read()
        except Exception:
            return
        try:
            root = ET.fromstring(blob)
        except Exception:
            for m in re.findall(rb"<loc>(.+?)</loc>", blob):
                data["sitemap_urls"].append(m.decode("utf-8", "ignore"))
            return
        ns = root.tag.split("}")[0].strip("{") if "}" in root.tag else ""
        prefix = f"{{{ns}}}" if ns else ""
        if root.tag.endswith("sitemapindex"):
            for sm in root.findall(f"{prefix}sitemap/{prefix}loc"):
                if sm.text:
                    data["sitemaps"].append(sm.text.strip())
                    await self._fetch_sitemap(session, sm.text.strip(), data, depth + 1)
        else:
            for u in root.findall(f"{prefix}url/{prefix}loc"):
                if u.text:
                    data["sitemap_urls"].append(u.text.strip())


ModuleRegistry.register(RobotsSitemapAnalyzer())
