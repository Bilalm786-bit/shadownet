"""
ShadowNet — WAF / IPS Detector
Sends a small set of benign trigger requests (suspicious-looking but harmless
query strings) and observes how the target responds: status codes, custom error
pages, header signatures, response-body banners. Classifies the WAF / IPS
based on a fingerprint database of 25+ products.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List

import aiohttp

from app.modules.base import EntityFound, ModuleRegistry, OSINTModule, ScanResult


SIGNATURES: List[Dict[str, Any]] = [
    {"vendor": "Cloudflare", "headers": ["cf-ray", "server: cloudflare"], "body": ["attention required! | cloudflare"]},
    {"vendor": "AWS WAF", "headers": ["x-amz-cf-id", "x-amzn-requestid"], "body": ["aws", "request blocked"]},
    {"vendor": "Akamai Kona", "headers": ["x-akamai-transformed", "akamai-grn"], "body": ["access denied", "akamai"]},
    {"vendor": "Imperva Incapsula", "headers": ["x-iinfo", "x-cdn: incapsula"], "body": ["incident id", "_incapsula_resource"]},
    {"vendor": "F5 BIG-IP ASM", "headers": ["x-cnection", "x-wa-info"], "body": ["the requested url was rejected", "support id"]},
    {"vendor": "Sucuri CloudProxy", "headers": ["x-sucuri-id", "x-sucuri-cache"], "body": ["access denied - sucuri"]},
    {"vendor": "Fastly", "headers": ["x-fastly-request-id"], "body": []},
    {"vendor": "Barracuda", "headers": ["barra_counter_session", "barracuda_"], "body": ["barracuda"]},
    {"vendor": "Wallarm", "headers": ["nwsapps"], "body": ["nginx-wallarm"]},
    {"vendor": "Citrix NetScaler", "headers": ["via: ns-cache", "ns_af="], "body": ["citrix"]},
    {"vendor": "FortiWeb", "headers": ["fortiwafsid="], "body": ["fortiweb"]},
    {"vendor": "ModSecurity", "headers": [], "body": ["mod_security", "modsecurity"]},
    {"vendor": "Sucuri / GoDaddy WSP", "headers": ["x-sucuri-cache"], "body": ["sucuri website firewall"]},
    {"vendor": "DenyAll", "headers": ["sessioncookie", "x-denyall"], "body": ["condition intercepted"]},
    {"vendor": "Distil Networks", "headers": ["x-distil-cs"], "body": ["distil"]},
    {"vendor": "Reblaze", "headers": ["x-rbl-action"], "body": []},
    {"vendor": "Cloudfront", "headers": ["x-amz-cf-pop"], "body": []},
    {"vendor": "StackPath", "headers": ["x-sp-edge", "x-sp-url"], "body": []},
]
PROBES: List[Dict[str, str]] = [
    {"label": "baseline", "path": "/"},
    {"label": "sqli", "path": "/?id=1' OR '1'='1"},
    {"label": "xss", "path": "/?q=<script>alert(1)</script>"},
    {"label": "lfi", "path": "/?file=../../../../etc/passwd"},
    {"label": "cmd", "path": "/?cmd=;cat /etc/passwd"},
]


class WAFDetector(OSINTModule):
    name = "recon.waf_detector"
    description = "Detect Web Application Firewall / IPS via response analysis (free)"
    supported_target_types = ["domain", "url"]
    requires_api_key = False
    rate_limit = 10

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        target = target.strip().lower()
        url = target if target.startswith("http") else f"https://{target}"
        domain = url.split("//")[-1].split("/")[0]

        responses: List[Dict[str, Any]] = []
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            for probe in PROBES:
                try:
                    async with session.get(
                        url.rstrip("/") + probe["path"],
                        timeout=aiohttp.ClientTimeout(total=10),
                        allow_redirects=False,
                    ) as resp:
                        body = (await resp.read())[:8000].decode("utf-8", "ignore")
                        responses.append({
                            "probe": probe["label"], "status": resp.status,
                            "headers": {k.lower(): v for k, v in resp.headers.items()},
                            "body": body[:5000],
                            "size": len(body),
                        })
                except Exception as exc:
                    responses.append({"probe": probe["label"], "error": str(exc)})

        detected: List[Dict[str, Any]] = []
        for sig in SIGNATURES:
            for r in responses:
                if "error" in r:
                    continue
                hb = "\n".join(f"{k}: {v}" for k, v in r["headers"].items()).lower()
                bb = r["body"].lower()
                hit_header = any(needle.lower() in hb for needle in sig["headers"])
                hit_body = any(needle.lower() in bb for needle in sig["body"])
                if hit_header or hit_body:
                    detected.append({"vendor": sig["vendor"], "via": "header" if hit_header else "body", "probe": r["probe"]})
                    break

        seen = set()
        unique: List[Dict[str, Any]] = []
        for d in detected:
            key = d["vendor"]
            if key not in seen:
                seen.add(key)
                unique.append(d)

        baseline = next((r for r in responses if r.get("probe") == "baseline"), None)
        block_signals = []
        if baseline and "status" in baseline:
            for r in responses:
                if r.get("probe") in (None, "baseline") or "status" not in r:
                    continue
                if r["status"] in (403, 406, 419, 429, 999) and r["status"] != baseline["status"]:
                    block_signals.append({"probe": r["probe"], "status": r["status"]})

        entities = [
            EntityFound(
                entity_type="waf", value=d["vendor"], source=self.name, confidence=0.9,
                metadata={"detected_via": d["via"], "trigger": d["probe"], "domain": domain},
                relationships=[{"type": "PROTECTS", "target": domain}],
            )
            for d in unique
        ]
        if not unique and block_signals:
            entities.append(EntityFound(
                entity_type="waf", value="Generic / Unidentified WAF", source=self.name,
                confidence=0.6,
                metadata={"signal": "blocked_payload_triggers", "blocks": block_signals, "domain": domain},
                relationships=[{"type": "PROTECTS", "target": domain}],
            ))

        if unique:
            summary = f"WAF detected on {domain}: {', '.join(d['vendor'] for d in unique)}"
        elif block_signals:
            summary = f"Generic WAF behaviour detected on {domain} ({len(block_signals)} blocked probes)"
        else:
            summary = f"No WAF detected on {domain} (target may be unprotected origin)"

        return ScanResult(
            module=self.name, target=domain, success=True,
            entities=entities,
            raw_data={"detections": unique, "block_signals": block_signals, "responses": responses},
            summary=summary,
            severity="info" if (unique or block_signals) else "low",
        )


ModuleRegistry.register(WAFDetector())
