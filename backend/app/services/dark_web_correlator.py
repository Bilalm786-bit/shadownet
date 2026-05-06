"""
ShadowNet — Dark Web Correlator

Cross-references the asset inventory + findings produced by every module
(domain, IPs, emails, secrets, CVE IDs, technology versions, subdomains)
against multiple dark-web / breach / paste / OSINT sources:

  - darkweb.onion_search          (Ahmia.fi clearnet bridge to .onion)
  - breach.paste_monitor          (Pastebin / GitHub Gist / Ghostbin / etc.)
  - breach.breach_checker         (HIBP-style breach DB)
  - breach.google_dorker          (targeted Google dork queries)
  - breach.tavily_search          (AI-assisted dark-web aware search)
  - threat.intel_lookup           (10 live threat-intel feeds: URLhaus,
                                   ThreatFox, Feodo Tracker, OpenPhish,
                                   PhishTank, CISA KEV, NVD, OTX,
                                   GitHub advisories, Tor exit list,
                                   Spamhaus DROP/EDROP)

Returns a normalized payload that the frontend renders as a "Dark Web"
panel (no raw JSON):

    {
      "queries_run": int,
      "sources_consulted": [...],
      "indicators": [
        {"category": "breach"|"paste"|"onion"|"threat_intel"|"google_dork",
         "value": "...", "source": "...", "severity": "...",
         "description": "...", "url": "...", "first_seen": "...",
         "tags": [...]}
      ],
      "by_category": {"breach": N, "paste": N, "onion": N, ...},
      "summary": "...",
      "risk_uplift": int      # 0-30 — added to overall risk_score
    }
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List, Optional, Set

import structlog

from app.modules.base import ModuleRegistry, ScanResult

logger = structlog.get_logger(__name__)


SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _safe_run(name: str, target: str) -> "asyncio.Future[Optional[ScanResult]]":
    """Wrap a module scan in a 60s timeout + exception swallow."""
    module = ModuleRegistry.get(name)

    async def _run() -> Optional[ScanResult]:
        if not module:
            return None
        try:
            return await asyncio.wait_for(module.scan(target), timeout=60)
        except Exception as exc:
            logger.warning("dark_web_correlator: module failed", module=name, error=str(exc))
            return None

    return asyncio.ensure_future(_run())


class DarkWebCorrelator:
    """Cross-reference a target's discovered assets against dark-web sources."""

    SOURCE_MODULES = [
        "darkweb.onion_search",
        "breach.paste_monitor",
        "breach.breach_checker",
        "breach.google_dorker",
        "breach.tavily_search",
        "threat.intel_lookup",
    ]

    async def correlate(
        self,
        target: str,
        asset_inventory: Optional[Dict[str, Any]] = None,
        findings: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Build a dark-web correlation report for `target`.

        Uses asset_inventory + findings to pick the most useful queries
        (domain itself, public emails, leaked secrets, CVE ids, IP, ASN
        organisation), runs multiple dark-web modules in parallel and
        normalises the results.
        """
        asset_inventory = asset_inventory or {}
        findings = findings or []
        queries: List[str] = self._build_queries(target, asset_inventory, findings)

        sources_available = [
            name for name in self.SOURCE_MODULES if ModuleRegistry.get(name)
        ]

        per_query_results: List[Dict[str, Any]] = []
        sem = asyncio.Semaphore(4)

        async def run_query(query: str) -> None:
            async with sem:
                tasks = []
                for name in sources_available:
                    tasks.append(_safe_run(name, query))
                if not tasks:
                    return
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for name, result in zip(sources_available, results):
                    if isinstance(result, Exception) or result is None:
                        continue
                    per_query_results.append({"query": query, "module": name, "result": result})

        await asyncio.gather(*[run_query(q) for q in queries])

        indicators = self._normalize(per_query_results)
        indicators = self._dedupe(indicators)
        by_category = self._count_categories(indicators)
        risk_uplift = self._risk_uplift(indicators)
        summary = self._summarize(target, indicators, by_category, len(queries), len(sources_available))

        return {
            "queries_run": len(queries),
            "queries": queries[:25],
            "sources_consulted": sources_available,
            "indicator_count": len(indicators),
            "by_category": by_category,
            "by_severity": self._count_severity(indicators),
            "risk_uplift": risk_uplift,
            "indicators": indicators[:200],
            "summary": summary,
        }

    @staticmethod
    def _build_queries(
        target: str,
        asset_inventory: Dict[str, Any],
        findings: List[Dict[str, Any]],
    ) -> List[str]:
        out: List[str] = []
        seen: Set[str] = set()

        def push(value: Optional[str]) -> None:
            if not value:
                return
            v = str(value).strip()
            if not v or len(v) < 3 or len(v) > 100:
                return
            key = v.lower()
            if key in seen:
                return
            seen.add(key)
            out.append(v)

        push(target)
        domain = target.split("//")[-1].split("/")[0].split(":")[0]
        push(domain)
        if domain.startswith("www."):
            push(domain[4:])

        push(asset_inventory.get("ip"))

        for email in (asset_inventory.get("emails") or [])[:8]:
            push(email)

        for sub in (asset_inventory.get("subdomains") or [])[:6]:
            push(sub)

        for f in findings:
            cwe = f.get("cwe") or ""
            sev = f.get("severity")
            if sev not in ("critical", "high"):
                continue
            family = (f.get("family") or "").lower()
            if "secret" in family or "leaked" in (f.get("title") or "").lower():
                evidence = f.get("evidence") or ""
                m = re.search(r"AKIA[0-9A-Z]{6,}", evidence)
                if m:
                    push(m.group(0))
            if cwe in ("CWE-89", "CWE-79", "CWE-918", "CWE-611", "CWE-22"):
                push(f.get("affected"))

        if asset_inventory.get("asn_name"):
            push(asset_inventory["asn_name"])

        return out[:12]

    @staticmethod
    def _normalize(per_query_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        indicators: List[Dict[str, Any]] = []
        for entry in per_query_results:
            module: str = entry["module"]
            result: ScanResult = entry["result"]
            query: str = entry["query"]
            if not result or not getattr(result, "success", False):
                continue
            for ent in getattr(result, "entities", []) or []:
                category = DarkWebCorrelator._category_for(module, ent.entity_type)
                indicators.append({
                    "category": category,
                    "source": ent.source or module,
                    "module": module,
                    "value": ent.value,
                    "type": ent.entity_type,
                    "severity": (ent.metadata or {}).get("severity") or DarkWebCorrelator._severity(category, ent),
                    "description": (ent.metadata or {}).get("title")
                                   or (ent.metadata or {}).get("detail")
                                   or (ent.metadata or {}).get("description")
                                   or (result.summary if not getattr(ent, "metadata", None) else ""),
                    "url": (ent.metadata or {}).get("url"),
                    "first_seen": (ent.metadata or {}).get("first_seen"),
                    "tags": (ent.metadata or {}).get("tags", []),
                    "query": query,
                    "confidence": ent.confidence,
                })
        return indicators

    @staticmethod
    def _category_for(module: str, entity_type: str) -> str:
        if module.startswith("darkweb.") or "onion" in (entity_type or ""):
            return "onion"
        if module == "breach.paste_monitor" or entity_type == "paste":
            return "paste"
        if module == "breach.breach_checker" or "breach" in (entity_type or ""):
            return "breach"
        if module == "threat.intel_lookup":
            return "threat_intel"
        if module == "breach.google_dorker":
            return "google_dork"
        if module == "breach.tavily_search":
            return "ai_search"
        return "other"

    @staticmethod
    def _severity(category: str, ent: Any) -> str:
        meta_sev = (getattr(ent, "metadata", {}) or {}).get("severity")
        if meta_sev:
            return meta_sev
        return {
            "breach": "high",
            "paste": "high",
            "onion": "medium",
            "threat_intel": "medium",
            "google_dork": "medium",
            "ai_search": "low",
        }.get(category, "info")

    @staticmethod
    def _dedupe(indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen: Set[str] = set()
        out: List[Dict[str, Any]] = []
        indicators.sort(key=lambda x: -SEVERITY_RANK.get(x.get("severity", "info"), 0))
        for ind in indicators:
            key = (
                ind.get("category", ""),
                str(ind.get("value", ""))[:160].lower(),
                str(ind.get("url", ""))[:160].lower(),
            )
            sk = "|".join(key)
            if sk in seen:
                continue
            seen.add(sk)
            out.append(ind)
        return out

    @staticmethod
    def _count_categories(indicators: List[Dict[str, Any]]) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for ind in indicators:
            c = ind.get("category", "other")
            out[c] = out.get(c, 0) + 1
        return out

    @staticmethod
    def _count_severity(indicators: List[Dict[str, Any]]) -> Dict[str, int]:
        out: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for ind in indicators:
            s = ind.get("severity", "info")
            out[s] = out.get(s, 0) + 1
        return out

    @staticmethod
    def _risk_uplift(indicators: List[Dict[str, Any]]) -> int:
        weights = {"critical": 6, "high": 4, "medium": 2, "low": 1, "info": 0}
        total = sum(weights.get(i.get("severity", "info"), 0) for i in indicators)
        return min(30, total)

    @staticmethod
    def _summarize(
        target: str,
        indicators: List[Dict[str, Any]],
        by_category: Dict[str, int],
        queries: int,
        sources: int,
    ) -> str:
        if not indicators:
            return (
                f"Dark-web sweep of {target}: no breach / paste / .onion / threat-intel "
                f"matches across {queries} queries × {sources} sources."
            )
        cats = ", ".join(f"{c}={n}" for c, n in sorted(by_category.items(), key=lambda x: -x[1]))
        crit = sum(1 for i in indicators if i.get("severity") == "critical")
        high = sum(1 for i in indicators if i.get("severity") == "high")
        return (
            f"Dark-web sweep of {target}: **{len(indicators)} indicators** "
            f"({crit} critical, {high} high) across {sources} sources. "
            f"Distribution: {cats}."
        )


dark_web_correlator = DarkWebCorrelator()
