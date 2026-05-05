"""
ShadowNet — Threat Intelligence API
Real-time IOC feeds, lookups, and enrichment.
"""

from fastapi import APIRouter, Depends, Query, HTTPException
from typing import Optional, List
import asyncio
from datetime import datetime, timezone

from app.core.security import get_current_user
from app.threat_intel.feeds import threat_intel_aggregator, ALL_FEEDS

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])


@router.get("/status")
async def status(current_user: dict = Depends(get_current_user)):
    """Aggregate health/status of the threat-intel subsystem."""
    stats = threat_intel_aggregator.stats()
    return {
        "engine": "ShadowNet Threat Intelligence",
        "feeds_available": list(ALL_FEEDS.keys()),
        "stats": stats,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/feeds")
async def feeds(current_user: dict = Depends(get_current_user)):
    """List configured threat-intel feeds and their last refresh status."""
    info = []
    descriptions = {
        "urlhaus": ("Malicious URL distribution", "abuse.ch URLhaus", "url"),
        "threatfox": ("Multi-type IOCs (IP, URL, hash, domain)", "abuse.ch ThreatFox", "mixed"),
        "feodo": ("Active botnet C2 infrastructure", "abuse.ch Feodo Tracker", "ip"),
        "openphish": ("Live phishing URLs", "OpenPhish", "url"),
        "phishtank": ("Verified phishing URLs", "PhishTank", "url"),
        "cisa_kev": ("Known Exploited Vulnerabilities", "CISA", "cve"),
        "nvd": ("Recently published CVEs", "NIST NVD", "cve"),
        "otx": ("AlienVault OTX threat pulses", "AT&T Cybersecurity", "pulse"),
        "github_advisories": ("Reviewed security advisories (GHSA/CVE)", "GitHub", "advisory"),
        "tor_exits": ("Tor exit node IP list", "Tor Project", "ip"),
        "spamhaus": ("Criminal network blocks (DROP/EDROP)", "Spamhaus", "cidr"),
    }
    status_map = threat_intel_aggregator.refresh_status or {}
    for key in ALL_FEEDS:
        desc, vendor, ioc_type = descriptions.get(key, ("", "", ""))
        s = status_map.get(key, {})
        info.append({
            "id": key,
            "vendor": vendor,
            "description": desc,
            "ioc_type": ioc_type,
            "ok": s.get("ok"),
            "count": s.get("count", 0),
            "error": s.get("error"),
        })
    return {
        "feeds": info,
        "last_refresh": threat_intel_aggregator.last_refresh.isoformat() if threat_intel_aggregator.last_refresh else None,
    }


@router.post("/refresh")
async def refresh(
    feeds: Optional[List[str]] = None,
    current_user: dict = Depends(get_current_user),
):
    """Force-refresh threat-intel feeds (or a specific subset)."""
    result = await threat_intel_aggregator.refresh(feeds=feeds)
    # Strip fresh_indicators detail for API economy
    return {
        "ok": True,
        "total": result["total"],
        "fresh": result["fresh"],
        "status": result["status"],
        "last_refresh": result["last_refresh"],
    }


@router.get("/indicators")
async def list_indicators(
    type: Optional[str] = Query(None, description="ioc_type filter"),
    severity: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    limit: int = Query(50, le=500),
    current_user: dict = Depends(get_current_user),
):
    """Return latest cached indicators, with optional filters."""
    items = threat_intel_aggregator.latest(
        limit=limit, ioc_type=type, severity=severity, source=source,
    )
    return {
        "count": len(items),
        "indicators": items,
        "last_refresh": threat_intel_aggregator.last_refresh.isoformat() if threat_intel_aggregator.last_refresh else None,
    }


@router.get("/lookup")
async def lookup(
    value: str = Query(..., min_length=2, description="IOC value to look up (IP, domain, URL, hash, CVE)"),
    current_user: dict = Depends(get_current_user),
):
    """Look up an indicator across all cached threat-intel feeds."""
    matches = threat_intel_aggregator.lookup(value)
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    if matches:
        worst = max(matches, key=lambda m: severity_rank.get(m.get("severity", "info"), 0))
        verdict = worst.get("severity", "medium")
        sources = sorted({m.get("source", "") for m in matches if m.get("source")})
    else:
        verdict = "clean"
        sources = []
    return {
        "value": value,
        "matches": matches,
        "match_count": len(matches),
        "verdict": verdict,
        "sources": sources,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/summary")
async def summary(current_user: dict = Depends(get_current_user)):
    """High-level summary for dashboard widgets."""
    stats = threat_intel_aggregator.stats()
    latest_critical = threat_intel_aggregator.latest(limit=10, severity="critical")
    latest_high = threat_intel_aggregator.latest(limit=10, severity="high")
    latest_cve = threat_intel_aggregator.latest(limit=10, ioc_type="cve")
    latest_phish = [i for i in threat_intel_aggregator.indicators
                    if "phish" in (i.get("threat", "") + " " + ",".join(i.get("tags", []))).lower()][:10]
    return {
        "stats": stats,
        "latest_critical": latest_critical,
        "latest_high": latest_high[:10],
        "latest_cve": latest_cve,
        "latest_phishing": latest_phish,
    }
