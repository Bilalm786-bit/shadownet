"""
ShadowNet — CMS Plugin & Theme Enumerator
WordPress-aware enumerator that fingerprints version, lists discoverable plugins
and themes from /wp-content/ paths and the public REST API, and identifies
publicly-listed users via /wp-json/wp/v2/users. Read-only and rate-limited.
Falls back to generic CMS detection for non-WordPress targets.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List, Set
from urllib.parse import urljoin, urlparse

import aiohttp

from app.modules.base import EntityFound, ModuleRegistry, OSINTModule, ScanResult


WP_VERSION_RE = re.compile(r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([0-9.]+)["\']', re.I)
WP_PLUGIN_RE = re.compile(r"/wp-content/plugins/([a-zA-Z0-9_\-]+)/", re.I)
WP_THEME_RE = re.compile(r"/wp-content/themes/([a-zA-Z0-9_\-]+)/", re.I)


class CMSEnum(OSINTModule):
    name = "enumeration.cms_enum"
    description = "Fingerprint WordPress/Joomla/Drupal version, plugins, themes, users (free)"
    supported_target_types = ["domain", "url"]
    requires_api_key = False
    rate_limit = 5

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        target = target.strip().lower()
        url_base = target if target.startswith("http") else f"https://{target}"
        domain = urlparse(url_base).netloc
        data: Dict[str, Any] = {
            "cms": None, "version": None, "plugins": [], "themes": [], "users": [],
            "endpoints_found": [], "notes": [],
        }
        entities: List[EntityFound] = []

        connector = aiohttp.TCPConnector(ssl=False, limit=8)
        async with aiohttp.ClientSession(connector=connector) as session:
            home = await self._fetch_text(session, url_base)
            if not home:
                return ScanResult(module=self.name, target=domain, success=False,
                                  error=f"Could not fetch {url_base}")

            if "wp-content" in home or "wp-includes" in home or "wp-json" in home:
                data["cms"] = "WordPress"
                m = WP_VERSION_RE.search(home)
                if m:
                    data["version"] = m.group(1)
                plugins: Set[str] = set(WP_PLUGIN_RE.findall(home))
                themes: Set[str] = set(WP_THEME_RE.findall(home))

                for path in ("/feed/", "/?feed=rss2", "/wp-sitemap.xml", "/sitemap.xml"):
                    body = await self._fetch_text(session, urljoin(url_base, path))
                    plugins.update(WP_PLUGIN_RE.findall(body or ""))
                    themes.update(WP_THEME_RE.findall(body or ""))

                rest_endpoints = (
                    "/wp-json/", "/wp-json/wp/v2/users", "/wp-json/wp/v2/pages",
                    "/wp-json/wp/v2/posts", "/wp-json/wp/v2/types",
                    "/wp-json/oembed/1.0", "/xmlrpc.php",
                )
                for ep in rest_endpoints:
                    full = urljoin(url_base, ep)
                    status = await self._fetch_status(session, full)
                    if status and status < 400:
                        data["endpoints_found"].append({"url": full, "status": status})

                users_url = urljoin(url_base, "/wp-json/wp/v2/users")
                users_body = await self._fetch_text(session, users_url)
                if users_body:
                    for m in re.finditer(r'"slug":"([^"]+)"', users_body):
                        if m.group(1) not in data["users"]:
                            data["users"].append(m.group(1))

                data["plugins"] = sorted(plugins)
                data["themes"] = sorted(themes)
            else:
                if "Joomla" in home:
                    data["cms"] = "Joomla"
                elif "Drupal.settings" in home or "/sites/default/files" in home:
                    data["cms"] = "Drupal"
                elif "ghost-api" in home:
                    data["cms"] = "Ghost"

        if data["cms"]:
            entities.append(EntityFound(
                entity_type="technology", value=data["cms"], source=self.name, confidence=0.95,
                metadata={"category": "cms", "version": data["version"], "domain": domain},
                relationships=[{"type": "POWERED_BY", "target": domain}],
            ))
        for plugin in data["plugins"]:
            entities.append(EntityFound(
                entity_type="cms_plugin", value=plugin, source=self.name, confidence=0.9,
                metadata={"cms": data["cms"], "domain": domain},
                relationships=[{"type": "INSTALLED_ON", "target": domain}],
            ))
        for theme in data["themes"]:
            entities.append(EntityFound(
                entity_type="cms_theme", value=theme, source=self.name, confidence=0.9,
                metadata={"cms": data["cms"], "domain": domain},
                relationships=[{"type": "INSTALLED_ON", "target": domain}],
            ))
        for user in data["users"]:
            entities.append(EntityFound(
                entity_type="username", value=user, source=self.name, confidence=0.95,
                metadata={"role": "cms_user", "cms": data["cms"], "domain": domain},
                relationships=[{"type": "AUTHORS_ON", "target": domain}],
            ))

        if not data["cms"]:
            return ScanResult(
                module=self.name, target=domain, success=True, entities=entities,
                raw_data=data, summary=f"No major CMS fingerprint detected on {domain}",
                severity="info",
            )

        severity = "high" if data["users"] else ("medium" if data["plugins"] else "info")
        summary = (
            f"CMS {data['cms']} v{data.get('version', '?')} on {domain}: "
            f"{len(data['plugins'])} plugins | {len(data['themes'])} themes | "
            f"{len(data['users'])} users disclosed"
        )

        return ScanResult(
            module=self.name, target=domain, success=True, entities=entities,
            raw_data=data, summary=summary, severity=severity,
        )

    @staticmethod
    async def _fetch_text(session: aiohttp.ClientSession, url: str) -> str:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False, allow_redirects=True) as resp:
                if resp.status != 200:
                    return ""
                return await resp.text(errors="ignore")
        except Exception:
            return ""

    @staticmethod
    async def _fetch_status(session: aiohttp.ClientSession, url: str) -> int | None:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=8), ssl=False, allow_redirects=False) as resp:
                return resp.status
        except Exception:
            return None


ModuleRegistry.register(CMSEnum())
