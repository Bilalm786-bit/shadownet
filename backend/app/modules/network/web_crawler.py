"""
ShadowNet — Website Intelligence Crawler
Crawls target websites to extract emails, phone numbers, social links,
hidden endpoints, login pages, API paths, and metadata.
NO API key required.
"""

import aiohttp
import asyncio
import re
from urllib.parse import urljoin, urlparse
from typing import Dict, Any, List, Set
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry
import structlog

logger = structlog.get_logger(__name__)

EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', re.I)
PHONE_REGEX = re.compile(r'[\+]?[(]?[0-9]{1,4}[)]?[-\s\./0-9]{7,15}')
SOCIAL_PATTERNS = {
    "twitter": re.compile(r'https?://(?:www\.)?(?:twitter\.com|x\.com)/([a-zA-Z0-9_]+)', re.I),
    "linkedin": re.compile(r'https?://(?:www\.)?linkedin\.com/(?:in|company)/([a-zA-Z0-9_-]+)', re.I),
    "facebook": re.compile(r'https?://(?:www\.)?facebook\.com/([a-zA-Z0-9.]+)', re.I),
    "instagram": re.compile(r'https?://(?:www\.)?instagram\.com/([a-zA-Z0-9_.]+)', re.I),
    "github": re.compile(r'https?://(?:www\.)?github\.com/([a-zA-Z0-9_-]+)', re.I),
}

SENSITIVE_PROBE_PATHS = [
    "/robots.txt", "/sitemap.xml", "/.env", "/.git/HEAD",
    "/wp-admin/", "/admin/", "/api/", "/swagger/",
    "/.well-known/security.txt", "/crossdomain.xml",
]


class WebCrawler(OSINTModule):
    name = "network.web_crawler"
    description = "Website intelligence crawler — extracts emails, phones, social links, hidden endpoints (free, no key)"
    supported_target_types = ["domain", "url"]
    requires_api_key = False
    rate_limit = 5

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        options = options or {}
        domain = target.strip().lower()
        if not domain.startswith("http"):
            base_url = f"https://{domain}"
        else:
            base_url = domain
            domain = urlparse(domain).netloc

        max_depth = min(options.get("max_depth", 2), 3)
        max_pages = min(options.get("max_pages", 30), 50)
        entities = []
        crawl_data = {
            "emails": [], "phones": [], "social_profiles": {},
            "internal_links": [], "external_links": [],
            "sensitive_paths": [], "forms": [], "comments": [],
            "meta_info": {}, "pages_crawled": 0, "errors": [],
        }

        visited: Set[str] = set()
        to_visit = [(base_url, 0)]
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

        connector = aiohttp.TCPConnector(limit=10, ssl=False)
        async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
            while to_visit and len(visited) < max_pages:
                current_url, depth = to_visit.pop(0)
                if current_url in visited:
                    continue
                visited.add(current_url)
                try:
                    async with session.get(current_url, timeout=aiohttp.ClientTimeout(total=10), allow_redirects=True) as resp:
                        if resp.status != 200 or "text/html" not in resp.headers.get("Content-Type", ""):
                            continue
                        body = await resp.text(errors="ignore")
                        crawl_data["pages_crawled"] += 1
                        self._extract_emails(body, crawl_data)
                        self._extract_phones(body, crawl_data)
                        self._extract_social(body, crawl_data)
                        self._extract_forms(body, current_url, crawl_data)
                        self._extract_meta(body, crawl_data)
                        if depth < max_depth:
                            for link, internal in self._extract_links(body, current_url, domain):
                                if internal and link not in visited:
                                    to_visit.append((link, depth + 1))
                                    if link not in crawl_data["internal_links"]:
                                        crawl_data["internal_links"].append(link)
                                elif not internal and link not in crawl_data["external_links"]:
                                    crawl_data["external_links"].append(link)
                        await asyncio.sleep(0.5)
                except Exception as e:
                    crawl_data["errors"].append(f"{current_url}: {str(e)}")

            # Probe sensitive paths
            for path in SENSITIVE_PROBE_PATHS:
                probe_url = base_url.rstrip("/") + path
                try:
                    async with session.get(probe_url, timeout=aiohttp.ClientTimeout(total=5), allow_redirects=False) as resp:
                        if resp.status == 200:
                            crawl_data["sensitive_paths"].append({"url": probe_url, "status": 200})
                except Exception:
                    pass

        # Limit arrays
        crawl_data["internal_links"] = crawl_data["internal_links"][:100]
        crawl_data["external_links"] = crawl_data["external_links"][:50]

        # Build entities
        for email in crawl_data["emails"]:
            entities.append(EntityFound(
                entity_type="email", value=email, source=self.name, confidence=0.9,
                metadata={"found_on": domain},
                relationships=[{"type": "FOUND_ON", "target": domain}],
            ))
        for phone in crawl_data["phones"]:
            entities.append(EntityFound(
                entity_type="phone", value=phone, source=self.name, confidence=0.7,
                metadata={"found_on": domain},
                relationships=[{"type": "FOUND_ON", "target": domain}],
            ))
        for platform, profiles in crawl_data["social_profiles"].items():
            for profile in profiles:
                entities.append(EntityFound(
                    entity_type="social_profile", value=profile, source=self.name, confidence=0.9,
                    metadata={"platform": platform},
                    relationships=[{"type": "HAS_PROFILE", "target": domain}],
                ))
        for path in crawl_data["sensitive_paths"]:
            entities.append(EntityFound(
                entity_type="sensitive_endpoint", value=path["url"], source=self.name, confidence=0.85,
                metadata={"status": path.get("status")},
                relationships=[{"type": "EXPOSES_PATH", "target": domain}],
            ))

        parts = [f"Crawled {crawl_data['pages_crawled']} pages on {domain}"]
        if crawl_data["emails"]:
            parts.append(f"{len(crawl_data['emails'])} emails")
        if crawl_data["sensitive_paths"]:
            parts.append(f"{len(crawl_data['sensitive_paths'])} sensitive paths")

        severity = "high" if crawl_data["sensitive_paths"] else ("medium" if crawl_data["emails"] else "info")

        return ScanResult(
            module=self.name, target=domain, success=True,
            entities=entities, raw_data=crawl_data,
            summary=" | ".join(parts), severity=severity,
        )

    def _extract_emails(self, body: str, data: dict):
        for email in EMAIL_REGEX.findall(body):
            email = email.lower()
            if email not in data["emails"] and not email.endswith(('.png', '.jpg', '.gif', '.svg', '.css', '.js')):
                data["emails"].append(email)

    def _extract_phones(self, body: str, data: dict):
        for phone in PHONE_REGEX.findall(body):
            phone = phone.strip()
            if len(phone) >= 10 and phone not in data["phones"] and len(data["phones"]) < 20:
                data["phones"].append(phone)

    def _extract_social(self, body: str, data: dict):
        for platform, pattern in SOCIAL_PATTERNS.items():
            if platform not in data["social_profiles"]:
                data["social_profiles"][platform] = []
            for match in pattern.findall(body):
                if match.lower() not in ("share", "intent", "sharer", "dialog"):
                    url = f"https://x.com/{match}" if platform == "twitter" else f"https://{platform}.com/{match}"
                    if url not in data["social_profiles"][platform]:
                        data["social_profiles"][platform].append(url)

    def _extract_links(self, body: str, current_url: str, domain: str) -> List[tuple]:
        links = []
        for href in re.findall(r'href=["\']([^"\']*)["\']', body, re.I):
            full = urljoin(current_url, href)
            parsed = urlparse(full)
            if parsed.scheme in ("http", "https"):
                full = full.split("#")[0]
                if full and len(full) < 500:
                    links.append((full, domain in parsed.netloc))
        return links

    def _extract_forms(self, body: str, url: str, data: dict):
        for form in re.finditer(r'<form[^>]*>(.*?)</form>', body[:50000], re.I | re.S):
            form_html = form.group(0)
            action = re.search(r'action=["\']([^"\']*)["\']', form_html, re.I)
            method = re.search(r'method=["\']([^"\']*)["\']', form_html, re.I)
            inputs = re.findall(r'<input[^>]*name=["\']([^"\']*)["\']', form_html, re.I)
            form_info = {
                "page_url": url,
                "action": action.group(1) if action else "",
                "method": method.group(1).upper() if method else "GET",
                "inputs": inputs[:10],
            }
            inputs_lower = " ".join(inputs).lower()
            if any(w in inputs_lower for w in ("password", "login", "signin")):
                form_info["type"] = "login"
            elif any(w in inputs_lower for w in ("file", "upload")):
                form_info["type"] = "upload"
            if len(data["forms"]) < 20:
                data["forms"].append(form_info)

    def _extract_meta(self, body: str, data: dict):
        for name, content in re.findall(
            r'<meta\s+[^>]*(?:name|property)=["\']([^"\']*)["\'][^>]*content=["\'](.*?)["\']',
            body[:20000], re.I
        ):
            if name.lower() in ("description", "keywords", "author", "generator"):
                data["meta_info"][name.lower()] = content[:200]


ModuleRegistry.register(WebCrawler())
