"""
ShadowNet — Technology Fingerprinting Module
Detects web technologies, CMS, WAF, JavaScript libraries, and server software.
NO API key required — uses HTTP headers and HTML analysis.
"""

import aiohttp
import re
from typing import Dict, Any, List
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry
import structlog

logger = structlog.get_logger(__name__)

# Technology signatures
SERVER_SIGNATURES = {
    "nginx": "Nginx",
    "apache": "Apache",
    "iis": "Microsoft IIS",
    "litespeed": "LiteSpeed",
    "cloudflare": "Cloudflare",
    "openresty": "OpenResty",
    "gunicorn": "Gunicorn",
    "cowboy": "Cowboy (Erlang)",
    "caddy": "Caddy",
    "envoy": "Envoy Proxy",
}

WAF_SIGNATURES = {
    "cloudflare": {"headers": ["cf-ray", "cf-cache-status", "__cfduid"], "name": "Cloudflare"},
    "akamai": {"headers": ["x-akamai-transformed", "akamai-origin-hop"], "name": "Akamai"},
    "sucuri": {"headers": ["x-sucuri-id", "x-sucuri-cache"], "name": "Sucuri"},
    "incapsula": {"headers": ["x-iinfo", "x-cdn"], "name": "Imperva/Incapsula"},
    "fastly": {"headers": ["x-fastly-request-id", "fastly-restarts"], "name": "Fastly"},
    "aws_waf": {"headers": ["x-amzn-requestid", "x-amz-cf-id"], "name": "AWS WAF/CloudFront"},
    "stackpath": {"headers": ["x-sp-url", "x-sp-wl"], "name": "StackPath"},
}

CMS_SIGNATURES = {
    "wordpress": {
        "patterns": ["/wp-content/", "/wp-includes/", "wp-json", 'name="generator" content="WordPress'],
        "name": "WordPress",
    },
    "joomla": {
        "patterns": ["/media/jui/", "/components/com_", 'content="Joomla!'],
        "name": "Joomla",
    },
    "drupal": {
        "patterns": ["/sites/default/files", "Drupal.settings", "/misc/drupal.js"],
        "name": "Drupal",
    },
    "shopify": {
        "patterns": ["cdn.shopify.com", "Shopify.theme", "myshopify.com"],
        "name": "Shopify",
    },
    "wix": {
        "patterns": ["wix.com", "static.wixstatic.com", "X-Wix-"],
        "name": "Wix",
    },
    "squarespace": {
        "patterns": ["squarespace.com", "static1.squarespace.com"],
        "name": "Squarespace",
    },
    "ghost": {
        "patterns": ['"ghost-', "ghost-api", 'content="Ghost'],
        "name": "Ghost",
    },
    "magento": {
        "patterns": ["/skin/frontend/", "/mage/", "Mage.Cookies"],
        "name": "Magento",
    },
}

JS_LIBRARY_PATTERNS = {
    "React": [r"react\.production\.min\.js", r"__NEXT_DATA__", r"_reactRootContainer"],
    "Vue.js": [r"vue\.min\.js", r"vue\.runtime", r"__vue__", r"Vue\."],
    "Angular": [r"angular\.min\.js", r"ng-version", r"ng-app"],
    "jQuery": [r"jquery[\.-][\d\.]+\.min\.js", r"jquery\.min\.js"],
    "Next.js": [r"__NEXT_DATA__", r"_next/static"],
    "Nuxt.js": [r"__NUXT__", r"_nuxt/"],
    "Bootstrap": [r"bootstrap\.min\.(css|js)", r"bootstrap-"],
    "Tailwind CSS": [r"tailwindcss", r"tailwind\."],
    "Svelte": [r"svelte", r"__svelte"],
    "Alpine.js": [r"alpine\.min\.js", r"x-data"],
    "Lodash": [r"lodash\.min\.js"],
    "Moment.js": [r"moment\.min\.js"],
    "Google Analytics": [r"google-analytics\.com", r"gtag\(", r"GoogleAnalyticsObject"],
    "Google Tag Manager": [r"googletagmanager\.com"],
    "Hotjar": [r"hotjar\.com", r"_hjSettings"],
    "Sentry": [r"sentry\.io", r"Sentry\.init"],
    "Cloudflare": [r"cdnjs\.cloudflare\.com"],
}


class TechDetector(OSINTModule):
    name = "network.tech_detector"
    description = "Technology fingerprinting — detects CMS, frameworks, WAFs, JS libraries, and server software (free, no key)"
    supported_target_types = ["domain", "url"]
    requires_api_key = False
    rate_limit = 10

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        domain = target.strip().lower()
        if not domain.startswith("http"):
            url = f"https://{domain}"
        else:
            url = domain
            domain = domain.split("//")[1].split("/")[0]

        entities = []
        tech_stack = {
            "server": None,
            "cms": None,
            "waf": [],
            "js_libraries": [],
            "headers": {},
            "meta_tags": {},
            "cookies": [],
        }

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        }

        try:
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15), allow_redirects=True) as resp:
                    resp_headers = dict(resp.headers)
                    body = await resp.text(errors="ignore")
                    cookies = [c.key for c in resp.cookies.values()] if resp.cookies else []
                    tech_stack["cookies"] = cookies

                    # Analyze headers
                    self._detect_server(resp_headers, tech_stack)
                    self._detect_waf(resp_headers, tech_stack)
                    self._detect_headers(resp_headers, tech_stack)

                    # Analyze body
                    self._detect_cms(body, tech_stack)
                    self._detect_js_libraries(body, tech_stack)
                    self._detect_meta_tags(body, tech_stack)

        except Exception as e:
            return ScanResult(
                module=self.name, target=domain, success=False,
                error=f"Could not connect to {url}: {str(e)}",
            )

        # Build entities
        if tech_stack["server"]:
            entities.append(EntityFound(
                entity_type="technology", value=tech_stack["server"],
                source=self.name, confidence=0.95,
                metadata={"category": "web_server", "domain": domain},
                relationships=[{"type": "RUNS_ON", "target": domain}],
            ))

        if tech_stack["cms"]:
            entities.append(EntityFound(
                entity_type="technology", value=tech_stack["cms"],
                source=self.name, confidence=0.9,
                metadata={"category": "cms", "domain": domain},
                relationships=[{"type": "POWERED_BY", "target": domain}],
            ))

        for waf in tech_stack["waf"]:
            entities.append(EntityFound(
                entity_type="technology", value=waf,
                source=self.name, confidence=0.85,
                metadata={"category": "waf", "domain": domain},
                relationships=[{"type": "PROTECTED_BY", "target": domain}],
            ))

        for lib in tech_stack["js_libraries"]:
            entities.append(EntityFound(
                entity_type="technology", value=lib,
                source=self.name, confidence=0.8,
                metadata={"category": "js_framework", "domain": domain},
                relationships=[{"type": "USES_TECH", "target": domain}],
            ))

        # Summary
        techs = []
        if tech_stack["server"]:
            techs.append(f"Server: {tech_stack['server']}")
        if tech_stack["cms"]:
            techs.append(f"CMS: {tech_stack['cms']}")
        if tech_stack["waf"]:
            techs.append(f"WAF: {', '.join(tech_stack['waf'])}")
        if tech_stack["js_libraries"]:
            techs.append(f"JS: {', '.join(tech_stack['js_libraries'][:5])}")

        tech_count = sum([
            1 if tech_stack["server"] else 0,
            1 if tech_stack["cms"] else 0,
            len(tech_stack["waf"]),
            len(tech_stack["js_libraries"]),
        ])

        summary = f"Tech fingerprint for {domain}: {tech_count} technologies detected | {' | '.join(techs)}"

        return ScanResult(
            module=self.name, target=domain, success=True,
            entities=entities, raw_data=tech_stack,
            summary=summary, severity="info",
        )

    def _detect_server(self, headers: dict, tech_stack: dict):
        server = headers.get("Server", headers.get("server", "")).lower()
        powered_by = headers.get("X-Powered-By", headers.get("x-powered-by", ""))

        for sig, name in SERVER_SIGNATURES.items():
            if sig in server:
                tech_stack["server"] = name
                break

        if powered_by:
            tech_stack["headers"]["x-powered-by"] = powered_by

    def _detect_waf(self, headers: dict, tech_stack: dict):
        headers_lower = {k.lower(): v for k, v in headers.items()}
        for waf_id, waf_info in WAF_SIGNATURES.items():
            for h in waf_info["headers"]:
                if h.lower() in headers_lower:
                    if waf_info["name"] not in tech_stack["waf"]:
                        tech_stack["waf"].append(waf_info["name"])
                    break

    def _detect_headers(self, headers: dict, tech_stack: dict):
        interesting = ["X-Powered-By", "X-AspNet-Version", "X-Generator",
                        "X-Drupal-Cache", "X-Varnish", "X-Cache",
                        "X-CDN", "X-Request-ID", "Via"]
        for h in interesting:
            val = headers.get(h, headers.get(h.lower(), ""))
            if val:
                tech_stack["headers"][h] = val

    def _detect_cms(self, body: str, tech_stack: dict):
        body_lower = body[:50000].lower()
        for cms_id, cms_info in CMS_SIGNATURES.items():
            for pattern in cms_info["patterns"]:
                if pattern.lower() in body_lower:
                    tech_stack["cms"] = cms_info["name"]
                    return

    def _detect_js_libraries(self, body: str, tech_stack: dict):
        body_chunk = body[:80000]
        for lib_name, patterns in JS_LIBRARY_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, body_chunk, re.I):
                    if lib_name not in tech_stack["js_libraries"]:
                        tech_stack["js_libraries"].append(lib_name)
                    break

    def _detect_meta_tags(self, body: str, tech_stack: dict):
        generators = re.findall(
            r'<meta\s+[^>]*name=["\']generator["\'][^>]*content=["\'](.*?)["\']',
            body[:20000], re.I
        )
        for gen in generators:
            tech_stack["meta_tags"]["generator"] = gen.strip()


ModuleRegistry.register(TechDetector())
