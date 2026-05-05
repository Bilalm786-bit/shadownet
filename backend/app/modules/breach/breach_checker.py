"""
ShadowNet — Real Breach Intelligence Module
Checks emails/domains/usernames against REAL breach databases.
Sources (all free, no API key):
  1. XposedOrNot API — completely free, unlimited
  2. Have I Been Pwned — breach metadata list (free)
  3. BreachDirectory — web scraping fallback
  4. LeakCheck (free tier)
"""

import aiohttp
import asyncio
import json
import re
from typing import Dict, Any, List
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry
import structlog

logger = structlog.get_logger(__name__)


class BreachChecker(OSINTModule):
    name = "breach.breach_checker"
    description = "Real breach intelligence — checks emails/domains against XposedOrNot, HIBP, and breach databases (free, no key)"
    supported_target_types = ["email", "domain", "username"]
    requires_api_key = False
    rate_limit = 10

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        target = target.strip().lower()
        entities = []
        all_breaches = []
        sources_checked = []
        errors = []

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json",
        }
        connector = aiohttp.TCPConnector(limit=5, ssl=False)

        async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
            # Run all checks concurrently
            tasks = {
                "xposedornot": self._check_xposedornot(session, target),
                "hibp_breaches": self._check_hibp_breaches(session, target),
                "leakcheck": self._check_leakcheck_free(session, target),
                "breachdirectory": self._check_breachdirectory(session, target),
                "emailrep": self._check_emailrep(session, target),
            }
            
            keys = list(tasks.keys())
            results = await asyncio.gather(*tasks.values(), return_exceptions=True)

            for name, result in zip(keys, results):
                if isinstance(result, Exception):
                    errors.append(f"{name}: {str(result)}")
                elif result:
                    all_breaches.extend(result)
                    sources_checked.append(name)

        # Deduplicate by breach name
        seen = set()
        unique_breaches = []
        for b in all_breaches:
            key = b.get("breach_name", "").lower() + b.get("domain", "")
            if key and key not in seen:
                seen.add(key)
                unique_breaches.append(b)

        # Create entities
        for breach in unique_breaches:
            severity = "critical" if breach.get("password_exposed") else "high"
            entities.append(EntityFound(
                entity_type="breach",
                value=f"{breach.get('breach_name', 'Unknown')} ({breach.get('breach_date', 'N/A')})",
                source=self.name,
                confidence=breach.get("confidence", 0.8),
                metadata={
                    "breach_name": breach.get("breach_name"),
                    "breach_date": breach.get("breach_date"),
                    "domain": breach.get("domain"),
                    "data_types": breach.get("data_types", []),
                    "pwn_count": breach.get("pwn_count"),
                    "password_exposed": breach.get("password_exposed", False),
                    "source_api": breach.get("source"),
                    "description": breach.get("description", ""),
                },
                relationships=[{"type": "BREACHED_IN", "target": target}],
            ))

        # Determine overall severity
        has_password = any(b.get("password_exposed") for b in unique_breaches)
        overall_severity = "critical" if has_password else ("high" if unique_breaches else "info")

        total_records = sum(b.get("pwn_count", 0) for b in unique_breaches if b.get("pwn_count"))
        data_types = set()
        for b in unique_breaches:
            data_types.update(b.get("data_types", []))

        summary_parts = [
            f"Target: {target}",
            f"Breaches found: {len(unique_breaches)}",
            f"Sources checked: {len(sources_checked)}",
        ]
        if total_records:
            summary_parts.append(f"Total records exposed: {total_records:,}")
        if has_password:
            summary_parts.append("⚠️ PASSWORDS EXPOSED")
        if data_types:
            summary_parts.append(f"Data types: {', '.join(sorted(data_types)[:8])}")

        return ScanResult(
            module=self.name, target=target, success=True,
            entities=entities,
            raw_data={
                "breaches": unique_breaches,
                "total_breaches": len(unique_breaches),
                "total_records_exposed": total_records,
                "password_exposed": has_password,
                "data_types_leaked": sorted(data_types),
                "sources_checked": sources_checked,
                "errors": errors,
            },
            summary=" | ".join(summary_parts),
            severity=overall_severity,
        )

    async def _check_xposedornot(self, session: aiohttp.ClientSession, target: str) -> List[Dict]:
        """XposedOrNot — completely free breach API, no key needed."""
        breaches = []
        try:
            # Check if email is in breaches
            url = f"https://api.xposedornot.com/v1/check-email/{target}"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("breaches"):
                        breach_list = data["breaches"]
                        if isinstance(breach_list, list):
                            for item in breach_list:
                                if isinstance(item, str):
                                    breaches.append({
                                        "breach_name": item,
                                        "breach_date": "Unknown",
                                        "data_types": [],
                                        "password_exposed": False,
                                        "source": "xposedornot",
                                        "confidence": 0.85,
                                    })
                                elif isinstance(item, dict):
                                    breaches.append({
                                        "breach_name": item.get("breach", item.get("name", "Unknown")),
                                        "breach_date": item.get("breachdate", item.get("date", "Unknown")),
                                        "domain": item.get("domain", ""),
                                        "data_types": item.get("dataclasses", item.get("data_types", [])),
                                        "pwn_count": item.get("pwncount", item.get("records", 0)),
                                        "password_exposed": "Passwords" in str(item.get("dataclasses", [])),
                                        "description": item.get("description", ""),
                                        "source": "xposedornot",
                                        "confidence": 0.9,
                                    })
        except Exception as e:
            logger.debug("XposedOrNot check failed", error=str(e))

        # Also get breach analytics
        try:
            url2 = f"https://api.xposedornot.com/v1/breach-analytics?email={target}"
            async with session.get(url2, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    analytics = data.get("ExposedBreaches", {}).get("breaches_details", [])
                    for item in analytics:
                        name = item.get("breach", "")
                        if name and not any(b["breach_name"] == name for b in breaches):
                            breaches.append({
                                "breach_name": name,
                                "breach_date": item.get("xposed_date", "Unknown"),
                                "domain": item.get("domain", ""),
                                "data_types": item.get("xposed_data", "").split(", ") if item.get("xposed_data") else [],
                                "pwn_count": item.get("xposed_records", 0),
                                "password_exposed": "password" in item.get("xposed_data", "").lower(),
                                "description": item.get("details", ""),
                                "source": "xposedornot",
                                "confidence": 0.9,
                            })
        except Exception:
            pass

        return breaches

    async def _check_hibp_breaches(self, session: aiohttp.ClientSession, target: str) -> List[Dict]:
        """HIBP breach metadata list — free, no key for breach list."""
        breaches = []
        try:
            async with session.get(
                "https://haveibeenpwned.com/api/v3/breaches",
                headers={"User-Agent": "ShadowNet-OSINT"},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    # Match breaches related to target domain or name
                    for breach in data:
                        breach_json = json.dumps(breach).lower()
                        if target.lower() in breach_json:
                            breaches.append({
                                "breach_name": breach.get("Name", "Unknown"),
                                "breach_date": breach.get("BreachDate", "Unknown"),
                                "domain": breach.get("Domain", ""),
                                "data_types": breach.get("DataClasses", []),
                                "pwn_count": breach.get("PwnCount", 0),
                                "password_exposed": "Passwords" in breach.get("DataClasses", []),
                                "description": re.sub(r'<[^>]+>', '', breach.get("Description", "")),
                                "is_verified": breach.get("IsVerified", False),
                                "source": "haveibeenpwned",
                                "confidence": 0.95 if breach.get("IsVerified") else 0.7,
                            })
        except Exception as e:
            logger.debug("HIBP breaches check failed", error=str(e))
        return breaches

    async def _check_leakcheck_free(self, session: aiohttp.ClientSession, target: str) -> List[Dict]:
        """LeakCheck — free tier lookup."""
        breaches = []
        try:
            url = f"https://leakcheck.io/api/public?check={target}"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("success") and data.get("found"):
                        for src in data.get("sources", []):
                            if isinstance(src, dict):
                                breaches.append({
                                    "breach_name": src.get("name", "Unknown"),
                                    "breach_date": src.get("date", "Unknown"),
                                    "data_types": src.get("data", []),
                                    "password_exposed": True,
                                    "source": "leakcheck",
                                    "confidence": 0.85,
                                })
                            elif isinstance(src, str):
                                breaches.append({
                                    "breach_name": src,
                                    "breach_date": "Unknown",
                                    "data_types": [],
                                    "password_exposed": False,
                                    "source": "leakcheck",
                                    "confidence": 0.7,
                                })
        except Exception as e:
            logger.debug("LeakCheck failed", error=str(e))
        return breaches

    async def _check_breachdirectory(self, session: aiohttp.ClientSession, target: str) -> List[Dict]:
        """BreachDirectory.org — free API."""
        breaches = []
        try:
            url = f"https://breachdirectory.org/api/entries?search={target}"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    results = data.get("result", [])
                    if isinstance(results, list):
                        for entry in results[:10]:
                            if isinstance(entry, dict):
                                breaches.append({
                                    "breach_name": entry.get("sources", [entry.get("source", "Unknown")])[0] if isinstance(entry.get("sources"), list) else entry.get("source", "Unknown"),
                                    "breach_date": entry.get("date", "Unknown"),
                                    "data_types": ["Email", "Password"] if entry.get("has_password") else ["Email"],
                                    "password_exposed": bool(entry.get("has_password")),
                                    "password_hint": entry.get("password", "")[:3] + "***" if entry.get("password") else None,
                                    "source": "breachdirectory",
                                    "confidence": 0.8,
                                })
        except Exception as e:
            logger.debug("BreachDirectory failed", error=str(e))
        return breaches

    async def _check_emailrep(self, session: aiohttp.ClientSession, target: str) -> List[Dict]:
        """EmailRep.io — free email reputation lookup."""
        breaches = []
        if "@" not in target:
            return breaches
        try:
            async with session.get(
                f"https://emailrep.io/{target}",
                headers={"User-Agent": "ShadowNet-OSINT", "Accept": "application/json"},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("details", {}).get("data_breach"):
                        breaches.append({
                            "breach_name": "EmailRep Data Breach Flag",
                            "breach_date": "Flagged",
                            "data_types": data.get("details", {}).get("profiles", []),
                            "password_exposed": data.get("details", {}).get("credentials_leaked", False),
                            "description": f"Reputation: {data.get('reputation', 'N/A')} | Suspicious: {data.get('suspicious', 'N/A')} | Profiles: {', '.join(data.get('details', {}).get('profiles', []))}",
                            "source": "emailrep",
                            "confidence": 0.75,
                            "extra": {
                                "reputation": data.get("reputation"),
                                "suspicious": data.get("suspicious"),
                                "malicious_activity": data.get("details", {}).get("malicious_activity"),
                                "spam": data.get("details", {}).get("spam"),
                                "free_provider": data.get("details", {}).get("free_provider"),
                                "deliverable": data.get("details", {}).get("deliverable"),
                                "profiles": data.get("details", {}).get("profiles", []),
                            },
                        })
        except Exception as e:
            logger.debug("EmailRep check failed", error=str(e))
        return breaches


ModuleRegistry.register(BreachChecker())
