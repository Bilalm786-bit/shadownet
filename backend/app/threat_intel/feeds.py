"""
ShadowNet — Threat Intelligence Feed Aggregator
Pulls real-time IOCs from open-source threat feeds.
Maintains an in-memory cache + ring buffer of recent events for the live feed.
"""

import asyncio
import aiohttp
import csv
import io
import json
import re
import structlog
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Set
from collections import deque

logger = structlog.get_logger(__name__)

USER_AGENT = "ShadowNet-OSINT/2.0 (+https://shadownet.local)"
HTTP_TIMEOUT = aiohttp.ClientTimeout(total=20)


# ─────────────────────────────────────────────────────────
# Indicator data model
# ─────────────────────────────────────────────────────────
class Indicator(dict):
    """Lightweight IOC record (dict-backed for easy JSON serialization)."""

    @classmethod
    def make(
        cls,
        ioc_type: str,
        value: str,
        source: str,
        threat: str = "",
        severity: str = "medium",
        first_seen: Optional[str] = None,
        tags: Optional[List[str]] = None,
        reference: str = "",
        confidence: float = 0.85,
        extra: Optional[Dict[str, Any]] = None,
    ) -> "Indicator":
        return cls(
            ioc_type=ioc_type,
            value=value,
            source=source,
            threat=threat,
            severity=severity,
            first_seen=first_seen or datetime.now(timezone.utc).isoformat(),
            tags=tags or [],
            reference=reference,
            confidence=confidence,
            extra=extra or {},
        )


# ─────────────────────────────────────────────────────────
# Feed implementations — each returns List[Indicator]
# ─────────────────────────────────────────────────────────
async def _fetch_text(session: aiohttp.ClientSession, url: str) -> str:
    try:
        async with session.get(url, timeout=HTTP_TIMEOUT, ssl=False) as r:
            if r.status == 200:
                return await r.text()
    except Exception as e:
        logger.debug("fetch_text failed", url=url, error=str(e))
    return ""


async def _fetch_json(session: aiohttp.ClientSession, url: str) -> Any:
    try:
        async with session.get(url, timeout=HTTP_TIMEOUT, ssl=False) as r:
            if r.status == 200:
                return await r.json(content_type=None)
    except Exception as e:
        logger.debug("fetch_json failed", url=url, error=str(e))
    return None


async def feed_urlhaus(session: aiohttp.ClientSession, limit: int = 200) -> List[Indicator]:
    """abuse.ch URLhaus — recent malicious URLs (CSV)."""
    out: List[Indicator] = []
    text = await _fetch_text(session, "https://urlhaus.abuse.ch/downloads/csv_recent/")
    if not text:
        return out
    try:
        # Strip leading comment lines starting with #
        lines = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
        reader = csv.reader(lines)
        for row in reader:
            if len(row) < 8:
                continue
            try:
                _, dateadded, url, status, threat, tags_field, _, source_ref = row[:8]
            except ValueError:
                continue
            tags = [t.strip() for t in tags_field.split(",") if t.strip()]
            out.append(Indicator.make(
                ioc_type="url",
                value=url,
                source="urlhaus.abuse.ch",
                threat=threat or "malware_download",
                severity="high" if status == "online" else "medium",
                first_seen=dateadded,
                tags=tags,
                reference=source_ref,
                confidence=0.95,
                extra={"status": status},
            ))
            if len(out) >= limit:
                break
    except Exception as e:
        logger.warning("urlhaus parse failed", error=str(e))
    return out


async def feed_threatfox(session: aiohttp.ClientSession, limit: int = 300) -> List[Indicator]:
    """abuse.ch ThreatFox — recent IOCs (public CSV export, no auth)."""
    out: List[Indicator] = []
    text = await _fetch_text(session, "https://threatfox.abuse.ch/export/csv/recent/")
    if not text:
        return out
    try:
        # Strip leading comment lines
        lines = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
        reader = csv.reader(lines, skipinitialspace=True)
        # Header may be the first non-comment line — skip if it doesn't look like data
        rows = list(reader)
        if rows and rows[0] and rows[0][0].lower().startswith("first_seen"):
            rows = rows[1:]
        for row in rows[:limit]:
            if len(row) < 14:
                continue
            (first_seen, ioc_id, ioc_value, ioc_type_raw, threat_type,
             fk_malware, malware_alias, malware_printable, _last_seen,
             confidence, _compromised, reference, tags_field, _anon, *_rest) = row + [""] * (15 - len(row))
            ioc_type = ioc_type_raw.lower()
            norm = {
                "ip:port": "ip", "url": "url", "domain": "domain",
                "md5_hash": "hash_md5", "sha1_hash": "hash_sha1",
                "sha256_hash": "hash_sha256",
            }.get(ioc_type, ioc_type or "indicator")
            value = ioc_value
            if norm == "ip" and ":" in value:
                value = value.split(":")[0]
            try:
                conf = float(confidence) / 100.0
            except (TypeError, ValueError):
                conf = 0.75
            tags = [t.strip() for t in tags_field.split(",") if t.strip()]
            out.append(Indicator.make(
                ioc_type=norm,
                value=value,
                source="threatfox.abuse.ch",
                threat=malware_printable or threat_type or "malware",
                severity="high",
                first_seen=first_seen,
                tags=tags or [threat_type] if threat_type else tags,
                reference=f"https://threatfox.abuse.ch/ioc/{ioc_id}/",
                confidence=conf,
                extra={
                    "malware_alias": malware_alias,
                    "threat_type": threat_type,
                    "external_reference": reference,
                },
            ))
    except Exception as e:
        logger.warning("threatfox parse failed", error=str(e))
    return out


async def feed_feodo_tracker(session: aiohttp.ClientSession, limit: int = 200) -> List[Indicator]:
    """abuse.ch Feodo Tracker — active botnet C2 IPs."""
    out: List[Indicator] = []
    data = await _fetch_json(session, "https://feodotracker.abuse.ch/downloads/ipblocklist.json")
    if not isinstance(data, list):
        return out
    for item in data[:limit]:
        out.append(Indicator.make(
            ioc_type="ip",
            value=item.get("ip_address", ""),
            source="feodotracker.abuse.ch",
            threat=f"C2 — {item.get('malware', 'botnet')}",
            severity="critical",
            first_seen=item.get("first_seen"),
            tags=["c2", "botnet", item.get("malware", "").lower()],
            reference="https://feodotracker.abuse.ch/",
            confidence=0.95,
            extra={"port": item.get("port"), "as_number": item.get("as_number"),
                   "country": item.get("country"), "hostname": item.get("hostname")},
        ))
    return out


async def feed_openphish(session: aiohttp.ClientSession, limit: int = 200) -> List[Indicator]:
    """OpenPhish — live phishing URL feed."""
    out: List[Indicator] = []
    text = await _fetch_text(session, "https://openphish.com/feed.txt")
    if not text:
        return out
    for url in text.splitlines()[:limit]:
        url = url.strip()
        if not url:
            continue
        out.append(Indicator.make(
            ioc_type="url",
            value=url,
            source="openphish.com",
            threat="phishing",
            severity="high",
            tags=["phishing"],
            reference="https://openphish.com/",
            confidence=0.9,
        ))
    return out


async def feed_phishtank(session: aiohttp.ClientSession, limit: int = 200) -> List[Indicator]:
    """PhishTank — verified phishing URLs (public download, no key)."""
    out: List[Indicator] = []
    # Try the gzipped public download (no key required)
    try:
        async with session.get(
            "http://data.phishtank.com/data/online-valid.json",
            timeout=HTTP_TIMEOUT,
            ssl=False,
            headers={"User-Agent": USER_AGENT},
        ) as r:
            if r.status != 200:
                return out
            data = await r.json(content_type=None)
    except Exception as e:
        logger.debug("phishtank fetch failed", error=str(e))
        return out
    if not isinstance(data, list):
        return out
    for item in data[:limit]:
        url = item.get("url", "")
        if not url:
            continue
        out.append(Indicator.make(
            ioc_type="url",
            value=url,
            source="phishtank.org",
            threat=f"phishing — {item.get('target', 'unknown brand')}",
            severity="high",
            first_seen=item.get("verification_time"),
            tags=["phishing", "verified"],
            reference=item.get("phish_detail_url", ""),
            confidence=0.95,
            extra={"target": item.get("target")},
        ))
    return out


async def feed_github_advisories(session: aiohttp.ClientSession, limit: int = 50) -> List[Indicator]:
    """GitHub Advisory Database — recent reviewed CVEs/GHSAs (no key, public)."""
    out: List[Indicator] = []
    data = await _fetch_json(
        session,
        f"https://api.github.com/advisories?per_page={limit}&type=reviewed",
    )
    if not isinstance(data, list):
        return out
    for item in data[:limit]:
        ghsa = item.get("ghsa_id") or item.get("cve_id")
        if not ghsa:
            continue
        sev = (item.get("severity") or "medium").lower()
        if sev not in ("critical", "high", "medium", "low"):
            sev = "medium"
        out.append(Indicator.make(
            ioc_type="advisory",
            value=ghsa,
            source="github.com/advisories",
            threat=item.get("summary") or "GitHub security advisory",
            severity=sev,
            first_seen=item.get("published_at"),
            tags=["advisory", "ghsa"] + ([item.get("cve_id")] if item.get("cve_id") else []),
            reference=item.get("html_url") or item.get("url", ""),
            confidence=1.0,
            extra={
                "cve_id": item.get("cve_id"),
                "ghsa_id": item.get("ghsa_id"),
                "cwe_ids": [c.get("cwe_id") for c in (item.get("cwes") or [])],
                "cvss_score": (item.get("cvss") or {}).get("score"),
                "vulnerabilities": [
                    {
                        "package": ((v.get("package") or {}).get("name")),
                        "ecosystem": ((v.get("package") or {}).get("ecosystem")),
                        "vulnerable_version_range": v.get("vulnerable_version_range"),
                    }
                    for v in (item.get("vulnerabilities") or [])[:5]
                ],
            },
        ))
    return out


async def feed_cisa_kev(session: aiohttp.ClientSession, limit: int = 100) -> List[Indicator]:
    """CISA Known Exploited Vulnerabilities catalog."""
    out: List[Indicator] = []
    data = await _fetch_json(
        session,
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    )
    if not isinstance(data, dict):
        return out
    vulns = data.get("vulnerabilities") or []
    # Latest entries first
    for item in reversed(vulns):
        cve_id = item.get("cveID")
        if not cve_id:
            continue
        out.append(Indicator.make(
            ioc_type="cve",
            value=cve_id,
            source="cisa.gov/kev",
            threat=item.get("vulnerabilityName", "Known Exploited Vulnerability"),
            severity="critical",
            first_seen=item.get("dateAdded"),
            tags=["kev", "exploited"] + ([item.get("vendorProject", "").lower()] if item.get("vendorProject") else []),
            reference=item.get("notes") or f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            confidence=1.0,
            extra={
                "vendor": item.get("vendorProject"),
                "product": item.get("product"),
                "due_date": item.get("dueDate"),
                "ransomware_use": item.get("knownRansomwareCampaignUse"),
                "short_description": item.get("shortDescription"),
            },
        ))
        if len(out) >= limit:
            break
    return out


async def feed_nvd_recent(session: aiohttp.ClientSession, limit: int = 50) -> List[Indicator]:
    """NVD recent published CVEs (last 7 days)."""
    out: List[Indicator] = []
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=7)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?pubStartDate={start.strftime(fmt)}&pubEndDate={end.strftime(fmt)}"
        f"&resultsPerPage={limit}"
    )
    data = await _fetch_json(session, url)
    if not isinstance(data, dict):
        return out
    for vuln in data.get("vulnerabilities") or []:
        cve = vuln.get("cve") or {}
        cve_id = cve.get("id")
        if not cve_id:
            continue
        descs = cve.get("descriptions") or []
        desc = next((d.get("value") for d in descs if d.get("lang") == "en"), "")
        metrics = cve.get("metrics") or {}
        sev = "medium"
        cvss = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                data_block = m.get("cvssData") or {}
                cvss = data_block.get("baseScore")
                sev_raw = (data_block.get("baseSeverity") or m.get("baseSeverity") or "").lower()
                if sev_raw in ("critical", "high", "medium", "low"):
                    sev = sev_raw
                break
        out.append(Indicator.make(
            ioc_type="cve",
            value=cve_id,
            source="nvd.nist.gov",
            threat=desc[:200] or "CVE record",
            severity=sev,
            first_seen=cve.get("published"),
            tags=["cve", "nvd"],
            reference=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            confidence=1.0,
            extra={"cvss": cvss, "description": desc},
        ))
    return out


async def feed_otx_pulses(session: aiohttp.ClientSession, limit: int = 30) -> List[Indicator]:
    """AlienVault OTX recent public pulses.

    OTX has gradually locked the public endpoints behind an API key. We attempt
    the un-authenticated routes and silently return empty if blocked — the
    aggregator still functions with the other 9 feeds.
    """
    out: List[Indicator] = []
    for path in ("activity/pulses", "pulses/subscribed", "search/pulses"):
        data = await _fetch_json(
            session,
            f"https://otx.alienvault.com/api/v1/{path}?limit={limit}",
        )
        if isinstance(data, dict) and data.get("results"):
            pulses = data["results"]
            break
    else:
        return out

    for pulse in pulses[:limit]:
        pid = pulse.get("id")
        name = pulse.get("name") or "OTX Pulse"
        tags = pulse.get("tags") or []
        ref = f"https://otx.alienvault.com/pulse/{pid}" if pid else ""
        out.append(Indicator.make(
            ioc_type="pulse",
            value=name,
            source="otx.alienvault.com",
            threat=name,
            severity="medium",
            first_seen=pulse.get("created"),
            tags=tags[:8],
            reference=ref,
            confidence=0.8,
            extra={
                "adversary": pulse.get("adversary"),
                "industries": pulse.get("industries", []),
                "targeted_countries": pulse.get("targeted_countries", []),
                "indicator_count": pulse.get("indicator_count", 0),
            },
        ))
    return out


async def feed_tor_exits(session: aiohttp.ClientSession, limit: int = 500) -> List[Indicator]:
    """Tor exit node list — useful for filtering/correlation."""
    out: List[Indicator] = []
    text = await _fetch_text(session, "https://check.torproject.org/torbulkexitlist")
    if not text:
        return out
    for ip in text.splitlines()[:limit]:
        ip = ip.strip()
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip):
            out.append(Indicator.make(
                ioc_type="ip",
                value=ip,
                source="check.torproject.org",
                threat="tor_exit_node",
                severity="low",
                tags=["tor", "anonymizer"],
                reference="https://check.torproject.org/",
                confidence=1.0,
            ))
    return out


async def feed_spamhaus_drop(session: aiohttp.ClientSession) -> List[Indicator]:
    """Spamhaus DROP/EDROP — networks under criminal control (CIDR blocks)."""
    out: List[Indicator] = []
    for url, label in (
        ("https://www.spamhaus.org/drop/drop.txt", "DROP"),
        ("https://www.spamhaus.org/drop/edrop.txt", "EDROP"),
    ):
        text = await _fetch_text(session, url)
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(";"):
                continue
            cidr = line.split(";")[0].strip()
            if not cidr:
                continue
            out.append(Indicator.make(
                ioc_type="cidr",
                value=cidr,
                source="spamhaus.org",
                threat=f"Spamhaus {label}",
                severity="high",
                tags=[label.lower(), "spamhaus", "criminal_network"],
                reference=url,
                confidence=0.95,
            ))
    return out


# ─────────────────────────────────────────────────────────
# Aggregator with in-memory cache
# ─────────────────────────────────────────────────────────
ALL_FEEDS = {
    "urlhaus": feed_urlhaus,
    "threatfox": feed_threatfox,
    "feodo": feed_feodo_tracker,
    "openphish": feed_openphish,
    "phishtank": feed_phishtank,
    "cisa_kev": feed_cisa_kev,
    "nvd": feed_nvd_recent,
    "otx": feed_otx_pulses,
    "github_advisories": feed_github_advisories,
    "tor_exits": feed_tor_exits,
    "spamhaus": feed_spamhaus_drop,
}


class ThreatIntelAggregator:
    """Maintains an in-memory aggregated view of all threat-intel feeds."""

    def __init__(self) -> None:
        self.indicators: List[Indicator] = []
        self.by_value: Dict[str, List[Indicator]] = {}
        self.by_type: Dict[str, List[Indicator]] = {}
        self.by_source: Dict[str, List[Indicator]] = {}
        self.last_refresh: Optional[datetime] = None
        self.refresh_status: Dict[str, Dict[str, Any]] = {}
        # Rolling buffer of newly seen indicators (for live feed broadcasts)
        self.recent_events: deque = deque(maxlen=200)
        self._known_keys: Set[str] = set()
        self._lock = asyncio.Lock()

    @staticmethod
    def _key(ind: Indicator) -> str:
        return f"{ind.get('source','')}::{ind.get('ioc_type','')}::{ind.get('value','')}"

    async def refresh(self, feeds: Optional[List[str]] = None) -> Dict[str, Any]:
        """Refresh selected feeds (or all)."""
        feed_names = feeds or list(ALL_FEEDS.keys())
        async with self._lock:
            connector = aiohttp.TCPConnector(limit=10, ssl=False)
            headers = {"User-Agent": USER_AGENT, "Accept": "application/json,text/plain,*/*"}
            new_indicators: List[Indicator] = []
            status: Dict[str, Dict[str, Any]] = {}

            async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
                tasks = [ALL_FEEDS[name](session) for name in feed_names if name in ALL_FEEDS]
                names = [n for n in feed_names if n in ALL_FEEDS]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for name, res in zip(names, results):
                    if isinstance(res, Exception):
                        status[name] = {"ok": False, "count": 0, "error": str(res)[:200]}
                    elif isinstance(res, list):
                        new_indicators.extend(res)
                        status[name] = {"ok": True, "count": len(res), "error": None}
                    else:
                        status[name] = {"ok": False, "count": 0, "error": "no data"}

            # Detect newly seen indicators (vs prior cache)
            fresh: List[Indicator] = []
            for ind in new_indicators:
                k = self._key(ind)
                if k not in self._known_keys:
                    self._known_keys.add(k)
                    fresh.append(ind)
                    self.recent_events.appendleft(ind)

            # Build/replace caches
            self.indicators = new_indicators
            self.by_value = {}
            self.by_type = {}
            self.by_source = {}
            for ind in new_indicators:
                self.by_value.setdefault(ind["value"].lower(), []).append(ind)
                self.by_type.setdefault(ind["ioc_type"], []).append(ind)
                self.by_source.setdefault(ind["source"], []).append(ind)

            self.last_refresh = datetime.now(timezone.utc)
            self.refresh_status = status

            logger.info(
                "Threat intel refreshed",
                total=len(new_indicators),
                fresh=len(fresh),
                feeds=len(status),
            )

            return {
                "total": len(new_indicators),
                "fresh": len(fresh),
                "status": status,
                "fresh_indicators": fresh[:50],
                "last_refresh": self.last_refresh.isoformat(),
            }

    # ─── Query helpers ──────────────────────────────────
    def lookup(self, value: str) -> List[Indicator]:
        v = (value or "").strip().lower()
        if not v:
            return []
        # Exact match first
        results = list(self.by_value.get(v, []))
        # Partial match for URLs / domains / hashes
        if not results:
            for k, items in self.by_value.items():
                if v in k or k in v:
                    results.extend(items)
                    if len(results) > 50:
                        break
        return results

    def stats(self) -> Dict[str, Any]:
        sev_counts: Dict[str, int] = {}
        for ind in self.indicators:
            sev_counts[ind.get("severity", "info")] = sev_counts.get(ind.get("severity", "info"), 0) + 1
        return {
            "total_indicators": len(self.indicators),
            "by_type": {k: len(v) for k, v in self.by_type.items()},
            "by_source": {k: len(v) for k, v in self.by_source.items()},
            "by_severity": sev_counts,
            "last_refresh": self.last_refresh.isoformat() if self.last_refresh else None,
            "feed_status": self.refresh_status,
            "recent_events_buffered": len(self.recent_events),
        }

    def latest(self, limit: int = 50, ioc_type: Optional[str] = None,
               severity: Optional[str] = None, source: Optional[str] = None) -> List[Indicator]:
        items = list(self.recent_events) or list(reversed(self.indicators))
        if ioc_type:
            items = [i for i in items if i.get("ioc_type") == ioc_type]
        if severity:
            items = [i for i in items if i.get("severity") == severity]
        if source:
            items = [i for i in items if i.get("source") == source]
        return items[:limit]


# Singleton
threat_intel_aggregator = ThreatIntelAggregator()
