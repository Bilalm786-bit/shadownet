"""
ShadowNet — Directory & File Buster
Async content-discovery scanner that probes a built-in wordlist of high-signal
paths (admin panels, backups, git/svn metadata, dotfiles, common CMS endpoints)
and reports those that respond with non-404 status codes. Concurrency-bounded
and rate-limited to avoid hammering targets.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse

import aiohttp

from app.modules.base import EntityFound, ModuleRegistry, OSINTModule, ScanResult


WORDLIST: List[str] = [
    "admin/", "administrator/", "wp-admin/", "wp-login.php", "login/", "signin/",
    "dashboard/", "cpanel/", "panel/", "manager/", "phpmyadmin/", "pma/", "adminer.php",
    "config/", "backup/", "backups/", "old/", "tmp/", "temp/", "test/", "dev/",
    "staging/", "beta/", "archive/", "private/", "internal/",
    ".git/HEAD", ".git/config", ".gitignore", ".svn/entries", ".hg/",
    ".env", ".env.local", ".env.production", ".env.example", "config.php.bak",
    "wp-config.php.bak", "database.sql", "db.sql", "dump.sql", "backup.sql",
    "backup.zip", "backup.tar.gz", "site.zip", "site.tar.gz", "www.zip",
    "phpinfo.php", "info.php", "test.php", "debug.php", "shell.php",
    "robots.txt", "sitemap.xml", "humans.txt", "security.txt", ".well-known/security.txt",
    "crossdomain.xml", "clientaccesspolicy.xml",
    "api/", "api/v1/", "api/v2/", "api/docs", "api/swagger", "swagger.json",
    "swagger-ui/", "openapi.json", "graphql", "graphql/playground",
    "actuator/", "actuator/health", "actuator/env", "actuator/heapdump",
    "metrics", "prometheus", "status", "healthz", "_health",
    "server-status", "server-info",  # Apache mod_status
    "console/", "h2-console/", "jolokia/",
    "uploads/", "files/", "downloads/", "public/", "static/", "assets/",
    ".DS_Store", "Thumbs.db", "web.config", ".htaccess", ".htpasswd",
    "composer.json", "composer.lock", "package.json", "package-lock.json",
    "yarn.lock", "Gemfile", "Gemfile.lock", "requirements.txt", "Dockerfile",
    "docker-compose.yml", ".dockerignore", "Makefile",
    "CHANGELOG", "CHANGELOG.md", "README.md", "LICENSE", "VERSION",
    "wp-content/uploads/", "wp-content/plugins/", "wp-content/themes/",
    "wp-json/", "wp-json/wp/v2/users/", "xmlrpc.php",
    "user/login", "user/register", "register", "signup", "logout",
    "password-reset", "forgot-password",
]


class DirectoryBuster(OSINTModule):
    name = "enumeration.directory_buster"
    description = "Async content-discovery: probe common admin / backup / config paths (free)"
    supported_target_types = ["domain", "url"]
    requires_api_key = False
    rate_limit = 5

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        options = options or {}
        target = target.strip().lower()
        url_base = target if target.startswith("http") else f"https://{target}"
        domain = urlparse(url_base).netloc
        wordlist: List[str] = options.get("wordlist") or WORDLIST
        concurrency: int = max(1, min(int(options.get("concurrency", 25)), 50))
        timeout: float = float(options.get("timeout", 8))

        sem = asyncio.Semaphore(concurrency)
        findings: List[Dict[str, Any]] = []
        headers = {"User-Agent": "ShadowNet/2 ContentDiscovery"}

        async def probe(session: aiohttp.ClientSession, path: str) -> None:
            url = urljoin(url_base.rstrip("/") + "/", path)
            async with sem:
                try:
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=timeout),
                        allow_redirects=False, ssl=False,
                    ) as resp:
                        status = resp.status
                        if status in (404, 410):
                            return
                        if status == 400:
                            return
                        body = await resp.read()
                        size = len(body)
                        is_soft_404 = (
                            status == 200 and size < 1500 and (
                                b"not found" in body.lower() or b"404" in body[:200].lower()
                            )
                        )
                        if is_soft_404:
                            return
                        findings.append({
                            "url": url, "status": status, "size": size,
                            "content_type": resp.headers.get("Content-Type", ""),
                            "redirect": resp.headers.get("Location") if 300 <= status < 400 else None,
                        })
                except Exception:
                    return

        connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
        async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
            await asyncio.gather(*[probe(session, p) for p in wordlist])

        findings.sort(key=lambda x: (x["status"], x["url"]))

        risky_keywords = (".git", ".env", "backup", "wp-config", "config.php", "phpinfo", "actuator", "server-status", "dump.sql", "shell.php", ".htpasswd")
        risky = [f for f in findings if any(k in f["url"].lower() for k in risky_keywords) and f["status"] in (200, 301, 302, 401, 403)]

        entities = []
        for f in findings:
            confidence = 0.95 if f["status"] in (200, 301, 302) else 0.6
            entity_type = "leaked_path" if any(k in f["url"].lower() for k in risky_keywords) else "discovered_path"
            entities.append(EntityFound(
                entity_type=entity_type, value=f["url"], source=self.name,
                confidence=confidence,
                metadata={"status": f["status"], "size": f["size"], "content_type": f["content_type"]},
                relationships=[{"type": "EXPOSES", "target": domain}],
            ))

        severity = "critical" if any(".env" in f["url"] or ".git/HEAD" in f["url"] or "wp-config" in f["url"] for f in risky) else (
            "high" if risky else ("medium" if findings else "info")
        )
        summary = (
            f"DirBust {domain}: {len(findings)} responsive paths "
            f"({len(risky)} sensitive) out of {len(wordlist)} probed"
        )

        return ScanResult(
            module=self.name, target=domain, success=True,
            entities=entities,
            raw_data={"findings": findings, "risky": risky, "wordlist_size": len(wordlist)},
            summary=summary, severity=severity,
        )


ModuleRegistry.register(DirectoryBuster())
