"""
ShadowNet — Advanced Dark Web Intelligence API
Multi-source dark web search with threat classification.
Sources: Ahmia.fi, breach databases, paste dorks, onion dorks.
All free, no API keys required.
"""

from fastapi import APIRouter, Depends, Query
from app.core.security import get_current_user
from app.modules.base import ModuleRegistry
from typing import Optional, List, Dict, Any
import aiohttp
import asyncio
import urllib.parse
import json
import re
from datetime import datetime, timezone
import structlog

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/darkweb", tags=["Dark Web"])

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
]


async def _fetch_html(session: aiohttp.ClientSession, url: str, params: dict = None, timeout: int = 20) -> str:
    for attempt in range(2):
        try:
            ua = USER_AGENTS[attempt % len(USER_AGENTS)]
            headers = {"User-Agent": ua, "Accept": "text/html,application/xhtml+xml", "Accept-Language": "en-US,en;q=0.9"}
            async with session.get(url, params=params, headers=headers,
                                   timeout=aiohttp.ClientTimeout(total=timeout),
                                   ssl=False, allow_redirects=True) as resp:
                if resp.status == 200:
                    return await resp.text()
        except Exception as e:
            logger.debug("Fetch attempt failed", url=url, attempt=attempt, error=str(e))
            if attempt < 1:
                await asyncio.sleep(1)
    return ""


async def _fetch_json(session: aiohttp.ClientSession, url: str, params: dict = None, timeout: int = 15) -> Any:
    try:
        headers = {"User-Agent": USER_AGENTS[0], "Accept": "application/json"}
        async with session.get(url, params=params, headers=headers,
                               timeout=aiohttp.ClientTimeout(total=timeout), ssl=False) as resp:
            if resp.status == 200:
                return await resp.json()
    except Exception as e:
        logger.debug("JSON fetch failed", url=url, error=str(e))
    return None


# ─── SOURCE: Ahmia.fi ──────────────────────────────────
async def _search_ahmia(session: aiohttp.ClientSession, query: str, limit: int) -> List[Dict]:
    results = []
    try:
        from bs4 import BeautifulSoup
        html = await _fetch_html(session, "https://ahmia.fi/search/", {"q": query})
        if not html:
            return []
        soup = BeautifulSoup(html, "html.parser")

        # Try multiple selector strategies
        selectors_list = [
            {"container": "li.result", "title": "h4", "link": "a", "desc": "p", "cite": "cite"},
            {"container": ".result", "title": "h4", "link": "a[href]", "desc": "p", "cite": "cite"},
            {"container": "li", "title": "h4,h3", "link": "a[href]", "desc": "p", "cite": "cite,code"},
        ]

        for sel in selectors_list:
            items = soup.select(sel["container"])[:limit]
            if not items:
                continue
            for item in items:
                title_el = item.select_one(sel["title"])
                link_el = item.select_one(sel["link"])
                desc_el = item.select_one(sel["desc"])
                cite_el = item.select_one(sel["cite"]) if sel.get("cite") else None

                url = ""
                if cite_el:
                    url = cite_el.get_text(strip=True)
                elif link_el:
                    href = link_el.get("href", "")
                    if "redirect" in href and "search_url=" in href:
                        parsed = urllib.parse.parse_qs(urllib.parse.urlparse(href).query)
                        url = parsed.get("search_url", [href])[0]
                    else:
                        url = href

                title = title_el.get_text(strip=True) if title_el else ""
                desc = desc_el.get_text(strip=True) if desc_el else ""
                if not title and not url:
                    continue

                results.append({
                    "title": title or "Untitled",
                    "url": url,
                    "description": desc[:500],
                    "source": "ahmia.fi",
                    "type": "onion_result",
                    "is_onion": ".onion" in url.lower(),
                })
            if results:
                break

        # Extract raw .onion URLs from page
        onion_pattern = r'https?://[a-z2-7]{16,56}\.onion[^\s"\'<>]*'
        raw_onions = list(set(re.findall(onion_pattern, html, re.IGNORECASE)))
        existing_urls = {r["url"] for r in results}
        for ou in raw_onions[:5]:
            if ou not in existing_urls:
                results.append({
                    "title": f"Hidden Service: {ou[:40]}...",
                    "url": ou, "description": "Onion address extracted from search",
                    "source": "ahmia.fi", "type": "onion_result", "is_onion": True,
                })
    except Exception as e:
        logger.warning("Ahmia search failed", error=str(e))
    return results


# ─── SOURCE: Torch (clearnet gateway) ─────────────────
async def _search_torch(session: aiohttp.ClientSession, query: str, limit: int) -> List[Dict]:
    results = []
    try:
        from bs4 import BeautifulSoup
        # Torch has a clearnet mirror
        html = await _fetch_html(session, "https://torchsearch.wordpress.com/", {"s": query}, timeout=15)
        if not html:
            return []
        soup = BeautifulSoup(html, "html.parser")
        for item in soup.select("article, .entry, .post")[:limit]:
            title_el = item.select_one("h2, h3, .entry-title")
            link_el = item.select_one("a[href]")
            desc_el = item.select_one("p, .entry-content")
            if title_el:
                results.append({
                    "title": title_el.get_text(strip=True)[:200],
                    "url": link_el.get("href", "") if link_el else "",
                    "description": desc_el.get_text(strip=True)[:300] if desc_el else "",
                    "source": "torch", "type": "onion_result",
                    "is_onion": ".onion" in (link_el.get("href", "") if link_el else ""),
                })
    except Exception as e:
        logger.debug("Torch search failed", error=str(e))
    return results


# ─── SOURCE: Breach Directory Check ───────────────────
async def _check_breach_directory(session: aiohttp.ClientSession, query: str) -> List[Dict]:
    results = []
    # HIBP public breaches list (no API key needed for breach metadata)
    try:
        headers = {
            "User-Agent": "ShadowNet-OSINT-Platform",
            "Accept": "application/json",
        }
        async with session.get(
            "https://haveibeenpwned.com/api/v3/breaches",
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=15),
            ssl=False,
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                matches = [b for b in data if query.lower() in json.dumps(b).lower()]
                for breach in matches[:10]:
                    results.append({
                        "title": f"Breach: {breach.get('Name', 'Unknown')}",
                        "url": f"https://haveibeenpwned.com/PwnedWebsites#{breach.get('Name', '')}",
                        "description": (
                            f"{breach.get('Title', '')} — {breach.get('BreachDate', 'N/A')} — "
                            f"{breach.get('PwnCount', 0):,} accounts. "
                            f"Data: {', '.join(breach.get('DataClasses', [])[:5])}"
                        ),
                        "source": "haveibeenpwned.com", "type": "breach", "severity": "critical",
                        "metadata": {
                            "breach_date": breach.get("BreachDate"),
                            "pwn_count": breach.get("PwnCount"),
                            "data_classes": breach.get("DataClasses", []),
                            "is_verified": breach.get("IsVerified"),
                        }
                    })
            elif resp.status == 403:
                # HIBP now requires API key — provide helpful dork instead
                results.append({
                    "title": f"HIBP Breach Check: {query}",
                    "url": f"https://haveibeenpwned.com/?q={urllib.parse.quote(query)}",
                    "description": "Check manually on HaveIBeenPwned.com (API requires paid key). Click to search.",
                    "source": "haveibeenpwned.com", "type": "breach_reference", "severity": "medium",
                })
    except Exception as e:
        logger.debug("HIBP check failed", error=str(e))

    # Dehashed search dork (free manual check)
    results.append({
        "title": f"Dehashed Search: {query}",
        "url": f"https://dehashed.com/search?query={urllib.parse.quote(query)}",
        "description": "Search Dehashed for leaked credentials and breach data. Free account available.",
        "source": "dehashed.com", "type": "breach_reference", "severity": "medium",
    })

    return results


# ─── SOURCE: Paste Site Dorks ─────────────────────────
async def _search_paste_sites(session: aiohttp.ClientSession, query: str, limit: int) -> List[Dict]:
    results = []
    dork_queries = [
        f'site:pastebin.com "{query}"',
        f'site:paste.ee "{query}"',
        f'site:dpaste.org "{query}"',
        f'site:ghostbin.com "{query}"',
        f'site:rentry.co "{query}"',
    ]
    for dork in dork_queries[:limit]:
        results.append({
            "title": f"Paste Dork: {dork[:60]}",
            "url": f"https://www.google.com/search?q={urllib.parse.quote(dork)}",
            "description": f"Search for '{query}' on paste sites. Click to execute.",
            "source": "paste_dork", "type": "dork_query", "severity": "info",
        })
    return results


# ─── SOURCE: Dark Web Dork Generator ─────────────────
async def _generate_onion_dorks(query: str) -> List[Dict]:
    dorks = [
        f'"{query}" site:*.onion.*',
        f'"{query}" inurl:onion',
        f'"{query}" "tor hidden service"',
        f'"{query}" "dark web" OR "darknet" leak OR breach OR dump',
        f'"{query}" filetype:sql OR filetype:csv "password" OR "email"',
        f'"{query}" "database dump" OR "data leak" OR "credentials"',
        f'"{query}" site:breachforums.is OR site:raidforums.com',
        f'"{query}" site:github.com password OR secret OR api_key',
        f'"{query}" site:trello.com OR site:notion.so password',
    ]
    results = []
    for dork in dorks:
        results.append({
            "title": f"Dork: {dork[:70]}",
            "url": f"https://www.google.com/search?q={urllib.parse.quote(dork)}",
            "description": "Intelligence dork query — may reveal dark web exposure.",
            "source": "darkweb_dork", "type": "dork_query", "severity": "info",
        })
    return results


# ─── SOURCE: GitHub Leak Search ───────────────────────
async def _search_github_leaks(session: aiohttp.ClientSession, query: str, limit: int) -> List[Dict]:
    results = []
    try:
        # GitHub code search API (unauthenticated, rate-limited)
        params = {"q": f'"{query}" password OR secret OR api_key', "per_page": min(limit, 10)}
        data = await _fetch_json(session, "https://api.github.com/search/code", params, timeout=10)
        if data and data.get("items"):
            for item in data["items"][:limit]:
                repo = item.get("repository", {})
                results.append({
                    "title": f"GitHub: {repo.get('full_name', 'unknown')}/{item.get('name', '')}",
                    "url": item.get("html_url", ""),
                    "description": f"Potential credential leak in {repo.get('full_name', '')}. File: {item.get('path', '')}",
                    "source": "github.com", "type": "code_leak", "severity": "high",
                })
    except Exception as e:
        logger.debug("GitHub leak search failed", error=str(e))

    # Always add GitHub dork as fallback
    if not results:
        results.append({
            "title": f"GitHub Code Search: {query}",
            "url": f"https://github.com/search?q={urllib.parse.quote(query + ' password OR secret')}&type=code",
            "description": "Search GitHub for leaked credentials. Click to search manually.",
            "source": "github.com", "type": "dork_query", "severity": "info",
        })
    return results


# ─── Email-specific breach check ─────────────────────
async def _check_email_breach(session: aiohttp.ClientSession, email: str) -> List[Dict]:
    results = []
    # IntelX free email search
    results.append({
        "title": f"IntelX Email Search: {email}",
        "url": f"https://intelx.io/?s={urllib.parse.quote(email)}",
        "description": "Search IntelX for email appearances in breaches and leaks. Free tier available.",
        "source": "intelx.io", "type": "breach_reference", "severity": "medium",
    })
    # Snusbase reference
    results.append({
        "title": f"Snusbase Search: {email}",
        "url": f"https://snusbase.com/",
        "description": f"Check '{email}' on Snusbase for breach data. Requires free account.",
        "source": "snusbase.com", "type": "breach_reference", "severity": "medium",
    })
    return results


def _apply_threat_classification(results: List[Dict]) -> List[Dict]:
    """Apply threat classification to all results."""
    try:
        from app.darkweb.threat_classifier import threat_classifier
        return threat_classifier.classify_batch(results)
    except Exception as e:
        logger.debug("Threat classification skipped", error=str(e))
        # Fallback: assign severity based on type
        for r in results:
            if not r.get("severity"):
                if r.get("type") == "breach":
                    r["severity"] = "critical"
                elif r.get("type") == "onion_result":
                    r["severity"] = "high"
                elif r.get("type") == "code_leak":
                    r["severity"] = "high"
                else:
                    r["severity"] = "info"
                r["threat_score"] = 0.0
                r["threat_categories"] = []
        return results


def _calculate_risk(classified_results: List[Dict]) -> Dict:
    """Calculate overall risk assessment."""
    try:
        from app.darkweb.threat_classifier import threat_classifier
        return threat_classifier.calculate_overall_risk(classified_results)
    except Exception:
        return {"risk_score": 0.0, "risk_level": "info", "severity_counts": {}, "total_iocs": 0}


# ═══════════════════════════════════════════════════════
# API ENDPOINTS
# ═══════════════════════════════════════════════════════

@router.get("/search")
async def search_darkweb(
    q: str = Query(..., min_length=1, description="Search query for dark web investigation"),
    limit: int = Query(20, le=50),
    current_user: dict = Depends(get_current_user),
):
    """
    Comprehensive dark web intelligence search.
    Runs all sources concurrently via asyncio.gather().
    """
    all_results = []
    sources_checked = []
    errors = []

    connector = aiohttp.TCPConnector(limit=10, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        # Build concurrent tasks
        coros = {
            "ahmia": _search_ahmia(session, q, limit),
            "torch": _search_torch(session, q, limit),
            "breaches": _check_breach_directory(session, q),
            "paste_sites": _search_paste_sites(session, q, limit),
            "github_leaks": _search_github_leaks(session, q, limit),
        }
        if "@" in q:
            coros["email_breach"] = _check_email_breach(session, q)

        # Execute ALL concurrently with asyncio.gather
        keys = list(coros.keys())
        tasks = list(coros.values())
        gathered = await asyncio.gather(*tasks, return_exceptions=True)

        results_map = {}
        for name, result in zip(keys, gathered):
            if isinstance(result, Exception):
                errors.append(f"{name}: {str(result)}")
                results_map[name] = []
            else:
                results_map[name] = result
                sources_checked.append(name)

    # Dork queries (no network needed)
    dork_results = await _generate_onion_dorks(q)
    results_map["darkweb_dorks"] = dork_results
    sources_checked.append("darkweb_dorks")

    # Merge with priority order
    priority_order = ["breaches", "email_breach", "ahmia", "torch", "github_leaks", "paste_sites", "darkweb_dorks"]
    for source in priority_order:
        if source in results_map:
            all_results.extend(results_map[source])

    # Apply threat classification
    classified = _apply_threat_classification(all_results)

    # Calculate risk
    risk_assessment = _calculate_risk(classified)

    # Summary stats
    type_counts = {}
    for r in classified:
        t = r.get("type", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1

    return {
        "query": q,
        "count": len(classified),
        "sources_checked": sources_checked,
        "risk_assessment": risk_assessment,
        "summary": {
            "breach_mentions": type_counts.get("breach", 0) + type_counts.get("breach_reference", 0),
            "onion_results": type_counts.get("onion_result", 0),
            "code_leaks": type_counts.get("code_leak", 0),
            "dork_queries": type_counts.get("dork_query", 0),
            "total": len(classified),
        },
        "results": classified[:limit],
        "errors": errors if errors else None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/scan")
async def scan_darkweb_target(
    q: str = Query(..., min_length=1, description="Target to scan on dark web"),
    current_user: dict = Depends(get_current_user),
):
    """Run the OnionCrawler OSINT module against a target."""
    module = ModuleRegistry.get("darkweb.onion_search")
    if not module:
        return {"query": q, "count": 0, "results": [], "error": "Dark web module not loaded"}

    try:
        result = await module.scan(q)
        return {
            "query": q,
            "count": len(result.entities),
            "summary": result.summary,
            "severity": result.severity,
            "results": result.raw_data.get("results", []),
            "entities": [
                {"type": e.entity_type, "value": e.value, "confidence": e.confidence, "metadata": e.metadata}
                for e in result.entities
            ],
        }
    except Exception as e:
        logger.error("Dark web scan failed", error=str(e))
        return {"query": q, "count": 0, "results": [], "error": str(e)}


@router.get("/breaches")
async def check_breaches(
    q: str = Query(..., min_length=1, description="Domain, email, or organization to check"),
    current_user: dict = Depends(get_current_user),
):
    """Check target against known data breach databases."""
    connector = aiohttp.TCPConnector(limit=5, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [_check_breach_directory(session, q)]
        if "@" in q:
            tasks.append(_check_email_breach(session, q))
        gathered = await asyncio.gather(*tasks, return_exceptions=True)

    all_results = []
    for r in gathered:
        if isinstance(r, list):
            all_results.extend(r)

    classified = _apply_threat_classification(all_results)
    return {
        "query": q,
        "count": len(classified),
        "results": classified,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/dorks")
async def get_darkweb_dorks(
    q: str = Query(..., min_length=1, description="Target for dork generation"),
    current_user: dict = Depends(get_current_user),
):
    """Generate dark web and breach-focused Google dork queries."""
    dorks = await _generate_onion_dorks(q)
    return {"query": q, "count": len(dorks), "dorks": dorks}


@router.get("/status")
async def darkweb_status(current_user: dict = Depends(get_current_user)):
    """Get dark web engine status including Tor connectivity."""
    try:
        from app.darkweb.tor_router import tor_router
        tor_status = await tor_router.get_status()
    except Exception:
        tor_status = {"connected": False, "error": "Tor router not available"}

    modules_loaded = []
    if ModuleRegistry.get("darkweb.onion_search"):
        modules_loaded.append("onion_search")

    try:
        from app.darkweb.threat_classifier import threat_classifier  # noqa: F401
        modules_loaded.append("threat_classifier")
    except Exception:
        pass

    sources = [
        {"name": "ahmia.fi", "type": "onion_search", "status": "active", "requires_key": False},
        {"name": "torch", "type": "onion_search", "status": "active", "requires_key": False},
        {"name": "haveibeenpwned.com", "type": "breach_check", "status": "limited", "requires_key": False,
         "note": "Breach list is free; per-email check requires API key"},
        {"name": "github.com", "type": "code_leak", "status": "active", "requires_key": False,
         "note": "Rate-limited without token"},
        {"name": "paste_dorks", "type": "dork_query", "status": "active", "requires_key": False},
        {"name": "darkweb_dorks", "type": "dork_query", "status": "active", "requires_key": False},
    ]

    return {
        "engine": "ShadowNet Dark Web Intelligence",
        "version": "2.0.0",
        "tor": tor_status,
        "modules_loaded": modules_loaded,
        "sources": sources,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/export")
async def export_results(
    q: str = Query(..., min_length=1),
    format: str = Query("json", regex="^(json|csv)$"),
    current_user: dict = Depends(get_current_user),
):
    """Export dark web search results in JSON or CSV format."""
    # Re-run search
    connector = aiohttp.TCPConnector(limit=10, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        coros = [
            _search_ahmia(session, q, 50),
            _check_breach_directory(session, q),
            _search_paste_sites(session, q, 50),
        ]
        gathered = await asyncio.gather(*coros, return_exceptions=True)

    all_results = []
    for r in gathered:
        if isinstance(r, list):
            all_results.extend(r)

    classified = _apply_threat_classification(all_results)

    if format == "csv":
        import csv
        import io
        from fastapi.responses import StreamingResponse
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["title", "url", "description", "source", "type", "severity", "threat_score"])
        writer.writeheader()
        for r in classified:
            writer.writerow({k: r.get(k, "") for k in writer.fieldnames})
        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=darkweb_{q}_{datetime.now().strftime('%Y%m%d')}.csv"}
        )

    return {
        "query": q,
        "count": len(classified),
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "results": classified,
    }
