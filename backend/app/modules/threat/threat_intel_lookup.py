"""
ShadowNet — Threat Intelligence Lookup Module
Cross-references a target (IP, domain, URL, hash, CVE) against:
  - Local threat-intel aggregator cache (URLhaus, ThreatFox, Feodo, OpenPhish,
    PhishTank, CISA KEV, NVD, OTX pulses, Tor exits, Spamhaus DROP)
  - On-demand AbuseIPDB / GreyNoise lightweight lookups (no key tier where possible)
"""

import re
import asyncio
import aiohttp
from typing import Dict, Any, List
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry
from app.threat_intel.feeds import threat_intel_aggregator
import structlog

logger = structlog.get_logger(__name__)


def _looks_like(target: str) -> str:
    t = target.strip()
    if re.match(r"^CVE-\d{4}-\d+$", t, re.IGNORECASE):
        return "cve"
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", t):
        return "ip"
    if re.match(r"^https?://", t):
        return "url"
    if re.match(r"^[a-fA-F0-9]{32}$", t):
        return "hash_md5"
    if re.match(r"^[a-fA-F0-9]{40}$", t):
        return "hash_sha1"
    if re.match(r"^[a-fA-F0-9]{64}$", t):
        return "hash_sha256"
    return "domain"


class ThreatIntelLookup(OSINTModule):
    name = "threat.intel_lookup"
    description = (
        "Real-time threat-intel correlation across URLhaus, ThreatFox, Feodo Tracker, "
        "OpenPhish, PhishTank, CISA KEV, NVD, AlienVault OTX, Tor exits, Spamhaus DROP."
    )
    supported_target_types = ["ip", "domain", "url", "hash", "cve", "username", "email"]
    requires_api_key = False

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        target = (target or "").strip()
        if not target:
            return ScanResult(module=self.name, target=target, success=False, error="Empty target")

        kind = _looks_like(target)

        # Ensure aggregator has data; if empty, refresh a minimal subset
        if not threat_intel_aggregator.indicators:
            try:
                await threat_intel_aggregator.refresh(
                    feeds=["urlhaus", "threatfox", "feodo", "openphish",
                           "cisa_kev", "spamhaus", "tor_exits"]
                )
            except Exception as e:
                logger.debug("threat-intel warmup failed", error=str(e))

        matches = threat_intel_aggregator.lookup(target)

        # Light-weight live cross-check: for IPs, also query AbuseIPDB-free
        # (no key — uses public abuse.ch ThreatFox query as fallback in the aggregator).
        live_lookups: List[Dict[str, Any]] = []
        if kind == "ip":
            live_lookups = await self._live_ip_check(target)
        elif kind == "url":
            live_lookups = await self._live_url_check(target)

        all_matches = list(matches) + live_lookups

        entities: List[EntityFound] = []
        sources: set = set()
        threats: set = set()
        worst_sev = "info"
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

        for m in all_matches:
            sources.add(m.get("source", ""))
            t = m.get("threat", "")
            if t:
                threats.add(t)
            sev = m.get("severity", "info")
            if sev_rank.get(sev, 0) > sev_rank.get(worst_sev, 0):
                worst_sev = sev
            entities.append(EntityFound(
                entity_type="threat_indicator",
                value=f"{m.get('ioc_type','')}:{m.get('value','')}",
                source=self.name,
                confidence=float(m.get("confidence", 0.85)),
                metadata={
                    "feed_source": m.get("source"),
                    "threat": t,
                    "severity": sev,
                    "tags": m.get("tags", []),
                    "first_seen": m.get("first_seen"),
                    "reference": m.get("reference"),
                },
                relationships=[{"type": "FLAGGED_BY", "target": m.get("source", "feed")}],
            ))

        if all_matches:
            summary = (
                f"⚠️ {target} matched {len(all_matches)} threat-intel indicators across "
                f"{len(sources)} feeds — verdict: {worst_sev.upper()}"
            )
            if threats:
                summary += f" | Threats: {', '.join(sorted(threats)[:4])}"
            severity = worst_sev
        else:
            summary = f"✅ {target} clean — no matches in {len(threat_intel_aggregator.indicators)} cached IOCs"
            severity = "info"

        return ScanResult(
            module=self.name,
            target=target,
            success=True,
            entities=entities,
            raw_data={
                "kind": kind,
                "matches": all_matches,
                "match_count": len(all_matches),
                "feeds_matched": sorted(sources),
                "threats": sorted(threats),
                "verdict": severity,
                "cached_indicator_count": len(threat_intel_aggregator.indicators),
            },
            summary=summary,
            severity=severity,
        )

    async def _live_ip_check(self, ip: str) -> List[Dict[str, Any]]:
        """Lightweight live IP reputation checks — no key required."""
        out: List[Dict[str, Any]] = []
        connector = aiohttp.TCPConnector(limit=4, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            # GreyNoise community endpoint (rate limited, no key)
            try:
                async with session.get(
                    f"https://api.greynoise.io/v3/community/{ip}",
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as r:
                    if r.status == 200:
                        data = await r.json()
                        if data.get("classification") and data.get("classification") != "unknown":
                            out.append({
                                "ioc_type": "ip",
                                "value": ip,
                                "source": "greynoise.io",
                                "threat": f"GreyNoise: {data.get('classification')} — {data.get('name', '')}",
                                "severity": "high" if data.get("classification") == "malicious" else "medium",
                                "tags": [data.get("classification", "")],
                                "reference": data.get("link", ""),
                                "confidence": 0.85,
                                "first_seen": data.get("last_seen"),
                            })
            except Exception:
                pass
            # AbuseIPDB lightweight (no-key) fallback via public API form
            # The real API requires a key, so we return a reference dork instead.
            out.append({
                "ioc_type": "ip",
                "value": ip,
                "source": "abuseipdb.com",
                "threat": "Manual reputation check available",
                "severity": "info",
                "tags": ["reference"],
                "reference": f"https://www.abuseipdb.com/check/{ip}",
                "confidence": 0.6,
            })
        return out

    async def _live_url_check(self, url: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        out.append({
            "ioc_type": "url",
            "value": url,
            "source": "urlscan.io",
            "threat": "Manual scan available",
            "severity": "info",
            "tags": ["reference"],
            "reference": f"https://urlscan.io/search/#{url}",
            "confidence": 0.6,
        })
        return out


ModuleRegistry.register(ThreatIntelLookup())
