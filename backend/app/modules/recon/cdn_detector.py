"""
ShadowNet — CDN / Reverse-Proxy Detector
Identifies the CDN, edge / proxy or cloud provider sitting in front of a website
by combining HTTP-header signatures, CNAME chain analysis and IP-prefix matching
against well-known cloud ranges. Free, no API key.
"""

from __future__ import annotations

import asyncio
import socket
from ipaddress import ip_address, ip_network
from typing import Any, Dict, List

import aiohttp
import dns.resolver

from app.modules.base import EntityFound, ModuleRegistry, OSINTModule, ScanResult


HEADER_SIGS: Dict[str, List[str]] = {
    "Cloudflare": ["cf-ray", "cf-cache-status", "server: cloudflare"],
    "Akamai": ["x-akamai-transformed", "akamai-origin-hop", "server: akamaighost"],
    "Fastly": ["x-fastly-request-id", "x-served-by: cache-", "x-cache: HIT, MISS"],
    "AWS CloudFront": ["x-amz-cf-id", "x-amz-cf-pop", "via: 1.1 .*cloudfront.net"],
    "Sucuri": ["x-sucuri-id", "x-sucuri-cache"],
    "Imperva / Incapsula": ["x-iinfo", "x-cdn: incapsula"],
    "Google Cloud LB": ["via: 1.1 google", "server: gws"],
    "Microsoft Azure CDN": ["x-azure-ref", "x-cache: TCP_HIT", "x-msedge-ref"],
    "StackPath": ["x-sp-url", "server: StackPath"],
    "KeyCDN": ["server: keycdn"],
    "BunnyCDN": ["server: bunnycdn", "cdn-cache: hit"],
    "Vercel": ["server: vercel", "x-vercel-cache"],
    "Netlify": ["server: netlify", "x-nf-request-id"],
}

CNAME_SIGS = {
    ".cloudflare.net": "Cloudflare",
    ".cloudflaressl.com": "Cloudflare",
    ".akamaiedge.net": "Akamai",
    ".akamaized.net": "Akamai",
    ".edgekey.net": "Akamai",
    ".fastly.net": "Fastly",
    ".cloudfront.net": "AWS CloudFront",
    ".elb.amazonaws.com": "AWS ELB",
    "azureedge.net": "Microsoft Azure CDN",
    ".azurewebsites.net": "Azure App Service",
    ".herokuapp.com": "Heroku",
    ".vercel.app": "Vercel",
    ".netlify.app": "Netlify",
    ".github.io": "GitHub Pages",
    ".pages.dev": "Cloudflare Pages",
    ".bunnycdn.com": "BunnyCDN",
    ".keycdn.com": "KeyCDN",
}

CLOUD_RANGES: Dict[str, List[str]] = {
    "Cloudflare": [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    ],
    "AWS CloudFront": ["13.32.0.0/15", "13.224.0.0/14", "52.84.0.0/15", "204.246.164.0/22"],
    "Google": ["8.34.208.0/20", "8.35.192.0/20", "34.64.0.0/10", "35.184.0.0/13"],
}


class CDNDetector(OSINTModule):
    name = "recon.cdn_detector"
    description = "Detect CDN / reverse proxy / cloud provider via headers, CNAME and IP ranges (free)"
    supported_target_types = ["domain", "url"]
    requires_api_key = False
    rate_limit = 10

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        target = target.strip().lower()
        domain = target.split("//")[-1].split("/")[0]
        url = target if target.startswith("http") else f"https://{domain}"

        detected: List[Dict[str, str]] = []
        raw: Dict[str, Any] = {"domain": domain, "headers": {}, "cnames": [], "ips": []}

        try:
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15), allow_redirects=True) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    raw["headers"] = headers
                    headers_blob = "\n".join(f"{k}: {v}" for k, v in headers.items()).lower()
                    for vendor, signatures in HEADER_SIGS.items():
                        if any(sig.lower() in headers_blob or sig.split(":")[0].lower() in headers for sig in signatures):
                            detected.append({"vendor": vendor, "via": "http_header"})
        except Exception as exc:
            raw["http_error"] = str(exc)

        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 5
            try:
                answers = resolver.resolve(domain, "CNAME")
                for r in answers:
                    cname = str(r.target).rstrip(".").lower()
                    raw["cnames"].append(cname)
                    for needle, vendor in CNAME_SIGS.items():
                        if needle in cname:
                            detected.append({"vendor": vendor, "via": f"cname:{cname}"})
            except Exception:
                pass
            try:
                a_answers = resolver.resolve(domain, "A")
                for r in a_answers:
                    raw["ips"].append(str(r))
            except Exception:
                pass
        except Exception:
            pass

        for ip in raw["ips"]:
            try:
                addr = ip_address(ip)
            except ValueError:
                continue
            for vendor, ranges in CLOUD_RANGES.items():
                if any(addr in ip_network(net) for net in ranges):
                    detected.append({"vendor": vendor, "via": f"ip_range:{ip}"})

        seen = set()
        unique: List[Dict[str, str]] = []
        for d in detected:
            key = (d["vendor"], d["via"].split(":")[0])
            if key not in seen:
                seen.add(key)
                unique.append(d)
        raw["detections"] = unique

        entities = []
        for d in unique:
            entities.append(EntityFound(
                entity_type="cdn", value=d["vendor"], source=self.name, confidence=0.9,
                metadata={"detected_via": d["via"], "domain": domain},
                relationships=[{"type": "FRONTS", "target": domain}],
            ))

        if unique:
            vendors = ", ".join(sorted({d["vendor"] for d in unique}))
            summary = f"CDN/Edge detected on {domain}: {vendors}"
        else:
            summary = f"No CDN signatures detected on {domain} (likely direct origin)"

        return ScanResult(
            module=self.name, target=domain, success=True,
            entities=entities, raw_data=raw, summary=summary,
            severity="info" if unique else "low",
        )


ModuleRegistry.register(CDNDetector())
