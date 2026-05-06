"""
ShadowNet — Investigation Orchestrator (v2 — Enhanced Person Investigation)
Manages the 3 investigation types: Person, Network, Website.
Person investigation now accepts structured seed data and runs smart module selection.
Spawns parallel module tasks, aggregates results, and generates AI reports.
"""

import asyncio
import re
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from app.modules.base import ModuleRegistry, ScanResult as ModuleScanResult
from app.services.ai_analyst import ai_analyst
from app.services.owasp_mapper import (
    annotate_finding as owasp_annotate,
    summary_stats as owasp_summary_stats,
    map_finding as owasp_map_finding,
)
from app.services.dark_web_correlator import dark_web_correlator
import structlog

logger = structlog.get_logger(__name__)

# ── Module Mapping for Each Investigation Type ──────────────
PERSON_MODULES = [
    "identity.email_validator",
    "identity.username_lookup",
    "identity.phone_lookup",
    "identity.social_analyzer",
    "identity.social_scraper",
    "identity.stealth_browser",
    "identity.cnic_lookup",
    "identity.whois_person",
    "identity.reverse_image",
    "breach.breach_checker",
    "breach.google_dorker",
    "breach.google_search",
    "breach.tavily_search",
    "breach.paste_monitor",
    "breach.stealth_scraper",
    "socmint.github_recon",
]

# Module → which seed data types it needs
MODULE_SEED_REQUIREMENTS = {
    "identity.email_validator": ["email"],
    "identity.phone_lookup": ["phone"],
    "identity.cnic_lookup": ["cnic"],
    "identity.username_lookup": ["username", "email", "person"],
    "identity.social_analyzer": ["username", "email", "person"],
    "identity.social_scraper": ["username", "email", "person"],
    "identity.stealth_browser": ["username", "email", "person"],
    "identity.whois_person": ["email", "person", "username"],
    "identity.reverse_image": ["photo_url"],
    "breach.breach_checker": ["email", "username", "person"],
    "breach.google_dorker": ["email", "username", "person", "phone", "cnic"],
    "breach.google_search": ["email", "username", "person", "phone"],
    "breach.tavily_search": ["email", "username", "person", "phone"],
    "breach.paste_monitor": ["email", "username"],
    "breach.stealth_scraper": ["email", "username", "person", "phone"],
    "socmint.github_recon": ["username"],
}

NETWORK_MODULES = [
    "network.dns_recon",
    "network.whois_lookup",
    "network.ip_geolocation",
    "network.port_scanner",
    "network.ssl_analyzer",
    "network.subdomain_enum",
    "network.shodan_free",
    "network.virustotal",
    "network.censys",
    "threat.intel_lookup",
    "breach.tavily_search",
    # ── Expanded passive network recon ─────────────────
    "recon.asn_lookup",
    "recon.cdn_detector",
    "recon.reverse_ip",
    "recon.http_fingerprint",
]

WEBSITE_MODULES = [
    "network.tech_detector",
    "network.web_crawler",
    "network.ssl_analyzer",
    "network.dns_recon",
    "network.whois_lookup",
    "network.subdomain_enum",
    "network.wayback_machine",
    "network.virustotal",
    "threat.intel_lookup",
    "breach.google_dorker",
    "breach.tavily_search",
    # ── Expanded website recon + enumeration ───────────
    "recon.cdn_detector",
    "recon.http_fingerprint",
    "recon.robots_sitemap",
    "enumeration.directory_buster",
    "enumeration.parameter_finder",
    "enumeration.js_endpoints",
    "enumeration.cms_enum",
    "enumeration.s3_buckets",
    "enumeration.vhost_enum",
    # ── Defensive exploitation surface checks ──────────
    "exploit.security_headers",
    "exploit.subdomain_takeover",
    "exploit.cors_misconfig",
    "exploit.open_redirect",
    "exploit.reflection_probe",
    "exploit.sqli_fingerprint",
    "exploit.secrets_scanner",
]

# ── Dedicated "Exploitation Surface" preset ───────────
EXPLOIT_MODULES = [
    "exploit.security_headers",
    "exploit.subdomain_takeover",
    "exploit.cors_misconfig",
    "exploit.open_redirect",
    "exploit.reflection_probe",
    "exploit.sqli_fingerprint",
    "exploit.secrets_scanner",
    "enumeration.directory_buster",
    "enumeration.js_endpoints",
    "enumeration.cms_enum",
    "enumeration.s3_buckets",
    "recon.robots_sitemap",
    "recon.http_fingerprint",
]


class InvestigationOrchestrator:
    """Orchestrates full investigations across Person/Network/Website categories."""

    async def investigate_person(
        self,
        target: str,
        seed_data: Dict[str, Any] = None,
        progress_cb=None,
    ) -> Dict[str, Any]:
        """
        Enhanced person investigation with structured seed data.
        seed_data can contain: username, email, phone, cnic, name, photo_url, aliases
        """
        seed_data = seed_data or {}
        target = target.strip()

        # Auto-detect what kind of target we got
        seed_types = self._detect_seed_types(target, seed_data)

        # Smart module selection: only run modules relevant to available seed data
        selected_modules = self._select_modules_for_seeds(seed_types)

        # Build target list: primary + all seed values
        targets_map = self._build_targets_map(target, seed_data, seed_types)

        return await self._run_person_investigation(
            target, selected_modules, targets_map, seed_data, progress_cb
        )

    def _detect_seed_types(self, target: str, seed_data: Dict) -> set:
        """Detect which seed data types are available."""
        types = set()

        # Auto-detect primary target type
        if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
            types.add("email")
        elif re.match(r'^[\+]?[0-9]{10,15}$', target.replace(" ", "").replace("-", "")):
            types.add("phone")
        elif re.match(r'^\d{5}-?\d{7}-?\d$', target.replace(" ", "")):
            types.add("cnic")
        else:
            types.add("username")
            types.add("person")

        # Add explicit seed data types
        if seed_data.get("email"):
            types.add("email")
        if seed_data.get("phone"):
            types.add("phone")
        if seed_data.get("cnic"):
            types.add("cnic")
        if seed_data.get("username"):
            types.add("username")
            types.add("person")
        if seed_data.get("name"):
            types.add("person")
        if seed_data.get("photo_url"):
            types.add("photo_url")
        if seed_data.get("aliases"):
            types.add("username")
            types.add("person")

        return types

    def _select_modules_for_seeds(self, seed_types: set) -> List[str]:
        """Select only modules that have relevant seed data."""
        selected = []
        for module_name in PERSON_MODULES:
            required_types = MODULE_SEED_REQUIREMENTS.get(module_name, ["person"])
            # Include module if ANY of its required types match available seed types
            if any(rt in seed_types for rt in required_types):
                selected.append(module_name)
        return selected

    def _build_targets_map(self, primary: str, seed_data: Dict, seed_types: set) -> Dict[str, str]:
        """Build a map of module → target value to use."""
        targets = {}

        email = seed_data.get("email") or (primary if "email" in seed_types and "@" in primary else "")
        phone = seed_data.get("phone") or (primary if "phone" in seed_types else "")
        cnic = seed_data.get("cnic") or (primary if "cnic" in seed_types else "")
        username = seed_data.get("username") or (primary.split("@")[0] if "@" in primary else primary)
        name = seed_data.get("name") or username
        photo_url = seed_data.get("photo_url", "")

        targets["identity.email_validator"] = email
        targets["identity.phone_lookup"] = phone
        targets["identity.cnic_lookup"] = cnic
        targets["identity.username_lookup"] = username
        targets["identity.social_analyzer"] = username
        targets["identity.social_scraper"] = username
        targets["identity.stealth_browser"] = username
        targets["identity.whois_person"] = email or name
        targets["identity.reverse_image"] = photo_url or username
        targets["breach.breach_checker"] = email or username
        targets["breach.google_dorker"] = email or name or username
        targets["breach.google_search"] = name or email or username
        targets["breach.tavily_search"] = name or email or username
        targets["breach.paste_monitor"] = email or username
        targets["breach.stealth_scraper"] = email or username
        targets["socmint.github_recon"] = username

        return targets

    async def _run_person_investigation(
        self,
        target: str,
        module_names: List[str],
        targets_map: Dict[str, str],
        seed_data: Dict[str, Any],
        progress_cb=None,
    ) -> Dict[str, Any]:
        """Execute person investigation with smart module targeting."""
        started = datetime.now(timezone.utc)

        report = {
            "category": "person",
            "target": target,
            "seed_data": {k: v for k, v in seed_data.items() if v},
            "started_at": started.isoformat(),
            "modules_run": [],
            "results": {},
            "entities_found": [],
            "ai_analysis": None,
            "breach_explanations": [],
            "risk_score": 0,
            "summary": "",
            "errors": [],
            "timeline": [],
            "phases": {
                "seed_data": {"status": "completed", "label": "Seed Data Collection"},
                "search_recon": {"status": "pending", "label": "Search Engine Recon"},
                "social_media": {"status": "pending", "label": "Social Media Profiling"},
                "username_enum": {"status": "pending", "label": "Username Enumeration"},
                "breach_data": {"status": "pending", "label": "Email & Breach Data"},
                "public_records": {"status": "pending", "label": "Public Records & WHOIS"},
                "image_geo": {"status": "pending", "label": "Image & Geolocation"},
                "correlation": {"status": "pending", "label": "Correlation & Reporting"},
            },
            "social_profiles": [],
        }

        # Filter to only available modules with valid targets
        available = []
        for m in module_names:
            mod = ModuleRegistry.get(m)
            tgt = targets_map.get(m, "")
            if mod and tgt:
                available.append((m, tgt))

        if not available:
            report["errors"].append("No modules available for person investigation")
            report["summary"] = "Investigation failed: no modules loaded"
            return report

        total = len(available)
        if progress_cb:
            await progress_cb({"phase": "scanning", "message": f"Running {total} modules...", "progress": 0, "total": total})

        # Phase mapping for progress
        phase_modules = {
            "search_recon": ["breach.google_dorker", "breach.google_search", "breach.tavily_search"],
            "social_media": ["identity.social_scraper", "identity.stealth_browser", "identity.social_analyzer", "socmint.github_recon"],
            "username_enum": ["identity.username_lookup"],
            "breach_data": ["breach.breach_checker", "breach.paste_monitor", "breach.stealth_scraper", "identity.email_validator"],
            "public_records": ["identity.cnic_lookup", "identity.whois_person", "identity.phone_lookup"],
            "image_geo": ["identity.reverse_image"],
        }

        # Run modules in batches of 4 concurrently
        primary_results = []
        for batch_start in range(0, total, 4):
            batch = available[batch_start:batch_start + 4]
            tasks = []
            for mod_name, mod_target in batch:
                module = ModuleRegistry.get(mod_name)
                if module:
                    # Pass avatar URLs to reverse_image if available
                    opts = {}
                    if mod_name == "identity.reverse_image":
                        avatars = [
                            e["metadata"].get("avatar_url", "")
                            for e in report["entities_found"]
                            if e.get("metadata", {}).get("avatar_url")
                        ]
                        if avatars:
                            opts["avatar_urls"] = avatars
                    tasks.append(self._run_module(module, mod_target, mod_name, opts))

            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, result in enumerate(batch_results):
                mod_name = batch[i][0]
                completed = batch_start + i + 1

                # Update phase status
                for phase_key, phase_mods in phase_modules.items():
                    if mod_name in phase_mods:
                        report["phases"][phase_key]["status"] = "running"

                if isinstance(result, Exception):
                    report["errors"].append(f"{mod_name}: {str(result)}")
                    report["timeline"].append({"module": mod_name, "status": "failed", "error": str(result)})
                elif result:
                    primary_results.append(result)
                    report["modules_run"].append(mod_name)
                    report["results"][mod_name] = {
                        "success": result.success,
                        "summary": result.summary,
                        "severity": result.severity,
                        "entity_count": len(result.entities),
                        "data": result.raw_data,
                    }
                    for entity in result.entities:
                        ent_dict = {
                            "type": entity.entity_type,
                            "value": entity.value,
                            "source": entity.source,
                            "confidence": entity.confidence,
                            "metadata": entity.metadata,
                        }
                        report["entities_found"].append(ent_dict)

                        # Collect social profiles for frontend display
                        if entity.entity_type == "social_profile":
                            report["social_profiles"].append({
                                "platform": entity.metadata.get("platform", ""),
                                "url": entity.value,
                                "username": entity.metadata.get("username", ""),
                                "display_name": entity.metadata.get("display_name", ""),
                                "bio": entity.metadata.get("bio", ""),
                                "followers": entity.metadata.get("followers", ""),
                                "following": entity.metadata.get("following", ""),
                                "posts_count": entity.metadata.get("posts_count", ""),
                                "avatar_url": entity.metadata.get("avatar_url", ""),
                                "verified": entity.metadata.get("verified", False),
                                "method": entity.metadata.get("extraction_method", ""),
                            })

                    report["timeline"].append({
                        "module": mod_name, "status": "completed",
                        "entities": len(result.entities), "severity": result.severity,
                    })

                # Mark completed phases
                for phase_key, phase_mods in phase_modules.items():
                    phase_completed = all(
                        any(t["module"] == pm for t in report["timeline"])
                        for pm in phase_mods
                        if any(m == pm for m, _ in available)
                    )
                    if phase_completed:
                        report["phases"][phase_key]["status"] = "completed"

                if progress_cb:
                    await progress_cb({"phase": "scanning", "message": f"Completed {mod_name}", "progress": completed, "total": total})

        # AI Analysis phase
        report["phases"]["correlation"]["status"] = "running"
        if progress_cb:
            await progress_cb({"phase": "ai_analysis", "message": "Running AI threat analysis..."})

        if ai_analyst.client:
            try:
                scan_data = [{"module": r.module, "summary": r.summary, "data": r.raw_data} for r in primary_results if r.success]
                analysis = await ai_analyst.analyze_scan_results(target, scan_data)
                report["ai_analysis"] = analysis.get("analysis")
                if analysis.get("analysis", {}).get("risk_score"):
                    report["risk_score"] = analysis["analysis"]["risk_score"]
            except Exception as e:
                report["errors"].append(f"AI analysis: {str(e)}")

            # Breach explanation
            breaches = [e for e in report["entities_found"] if e["type"] in ("breach", "breach_mention")]
            if breaches:
                try:
                    explanation = await ai_analyst.explain_breach(target, breaches)
                    report["breach_explanations"] = explanation
                except Exception as e:
                    report["errors"].append(f"Breach explanation: {str(e)}")
        else:
            severity_scores = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}
            risk = sum(severity_scores.get(r.severity, 0) for r in primary_results)
            report["risk_score"] = min(risk, 100)

        report["phases"]["correlation"]["status"] = "completed"

        # Build summary
        total_entities = len(report["entities_found"])
        total_modules = len(report["modules_run"])
        critical = sum(1 for r in primary_results if r.severity in ("critical", "high"))
        breach_count = sum(1 for e in report["entities_found"] if e["type"] in ("breach", "breach_mention"))
        social_count = len(report["social_profiles"])

        report["completed_at"] = datetime.now(timezone.utc).isoformat()
        report["summary"] = (
            f"PERSON investigation of {target}: "
            f"{total_modules} modules | {total_entities} entities | "
            f"{social_count} social profiles | "
            f"Risk: {report['risk_score']}/100 | "
            f"{critical} critical findings | {breach_count} breaches"
        )

        if progress_cb:
            await progress_cb({"phase": "complete", "message": report["summary"], "progress": 100, "total": 100})

        logger.info("Person investigation complete", target=target, entities=total_entities, risk=report["risk_score"])
        return report

    async def investigate_network(self, target: str, progress_cb=None) -> Dict[str, Any]:
        return await self._run_investigation("network", target, NETWORK_MODULES, progress_cb)

    async def investigate_website(self, target: str, progress_cb=None) -> Dict[str, Any]:
        return await self._run_investigation("website", target, WEBSITE_MODULES, progress_cb)

    async def investigate_exploit(self, target: str, progress_cb=None) -> Dict[str, Any]:
        """Run the exploitation-surface preset against a website / domain.
        Focused on enumeration + defensive vulnerability detection — every module
        in this preset is read-only and non-destructive.
        """
        return await self._run_investigation("exploit", target, EXPLOIT_MODULES, progress_cb)

    async def _run_investigation(
        self,
        category: str,
        target: str,
        module_names: list,
        progress_cb=None,
    ) -> Dict[str, Any]:
        target = target.strip()
        started = datetime.now(timezone.utc)

        report = {
            "category": category,
            "target": target,
            "started_at": started.isoformat(),
            "modules_run": [],
            "results": {},
            "entities_found": [],
            "ai_analysis": None,
            "breach_explanations": [],
            "risk_score": 0,
            "summary": "",
            "errors": [],
            "timeline": [],
        }

        available = [m for m in module_names if ModuleRegistry.get(m)]
        if not available:
            report["errors"].append(f"No modules available for {category}")
            report["summary"] = f"Investigation failed: no modules loaded"
            return report

        total = len(available)
        if progress_cb:
            await progress_cb({"phase": "scanning", "message": f"Running {total} modules...", "progress": 0, "total": total})

        primary_results = []
        for batch_start in range(0, total, 3):
            batch = available[batch_start:batch_start + 3]
            tasks = []
            for mod_name in batch:
                module = ModuleRegistry.get(mod_name)
                if module:
                    tasks.append(self._run_module(module, target, mod_name))

            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, result in enumerate(batch_results):
                mod_name = batch[i]
                completed = batch_start + i + 1
                if isinstance(result, Exception):
                    report["errors"].append(f"{mod_name}: {str(result)}")
                    report["timeline"].append({"module": mod_name, "status": "failed", "error": str(result)})
                elif result:
                    primary_results.append(result)
                    report["modules_run"].append(mod_name)
                    report["results"][mod_name] = {
                        "success": result.success,
                        "summary": result.summary,
                        "severity": result.severity,
                        "entity_count": len(result.entities),
                        "data": result.raw_data,
                    }
                    for entity in result.entities:
                        report["entities_found"].append({
                            "type": entity.entity_type,
                            "value": entity.value,
                            "source": entity.source,
                            "confidence": entity.confidence,
                            "metadata": entity.metadata,
                        })
                    report["timeline"].append({"module": mod_name, "status": "completed", "entities": len(result.entities), "severity": result.severity})

                if progress_cb:
                    await progress_cb({"phase": "scanning", "message": f"Completed {mod_name}", "progress": completed, "total": total})

        # AI Analysis phase
        if progress_cb:
            await progress_cb({"phase": "ai_analysis", "message": "Running AI threat analysis..."})

        if ai_analyst.client:
            try:
                scan_data = [{"module": r.module, "summary": r.summary, "data": r.raw_data} for r in primary_results if r.success]
                analysis = await ai_analyst.analyze_scan_results(target, scan_data)
                report["ai_analysis"] = analysis.get("analysis")
                if analysis.get("analysis", {}).get("risk_score"):
                    report["risk_score"] = analysis["analysis"]["risk_score"]
            except Exception as e:
                report["errors"].append(f"AI analysis: {str(e)}")

            breaches = [e for e in report["entities_found"] if e["type"] in ("breach", "breach_mention")]
            if breaches:
                try:
                    explanation = await ai_analyst.explain_breach(target, breaches)
                    report["breach_explanations"] = explanation
                except Exception as e:
                    report["errors"].append(f"Breach explanation: {str(e)}")
        else:
            severity_scores = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}
            risk = sum(severity_scores.get(r.severity, 0) for r in primary_results)
            report["risk_score"] = min(risk, 100)

        total_entities = len(report["entities_found"])
        total_modules = len(report["modules_run"])
        critical = sum(1 for r in primary_results if r.severity in ("critical", "high"))
        breach_count = sum(1 for e in report["entities_found"] if e["type"] in ("breach", "breach_mention"))

        # OWASP Top 10 coverage — synthesize findings from entities + module severity
        synthetic_findings: List[Dict[str, Any]] = []
        for ent in report["entities_found"]:
            if ent["type"] not in (
                "vulnerability", "leaked_secret", "leaked_path", "sensitive_endpoint",
                "missing_header", "info_disclosure", "cloud_bucket",
                "dns_misconfig", "email_misconfig",
            ):
                continue
            sev = (ent.get("metadata") or {}).get("severity") or "info"
            cwe = (ent.get("metadata") or {}).get("cwe")
            f = {
                "id": f"{ent['source']}:{ent['value']}",
                "plugin": ent["source"],
                "family": (ent.get("metadata") or {}).get("family", ""),
                "title": (ent.get("metadata") or {}).get("title") or ent["value"],
                "severity": sev,
                "cvss": (ent.get("metadata") or {}).get("cvss"),
                "cwe": cwe,
                "affected": (ent.get("metadata") or {}).get("url") or target,
            }
            owasp_annotate(f)
            synthetic_findings.append(f)
        if synthetic_findings:
            report["owasp_coverage"] = owasp_summary_stats(synthetic_findings)

        # Dark-web correlation phase
        if progress_cb:
            await progress_cb({"phase": "dark_web", "message": "Cross-referencing dark-web sources..."})
        try:
            asset_for_dw: Dict[str, Any] = {}
            for ent in report["entities_found"]:
                meta = ent.get("metadata") or {}
                if ent["type"] == "email":
                    asset_for_dw.setdefault("emails", []).append(ent["value"])
                if ent["type"] == "domain":
                    asset_for_dw.setdefault("subdomains", []).append(ent["value"])
                if ent["type"] in ("ip", "ip_address"):
                    asset_for_dw["ip"] = ent["value"]
                if meta.get("ip"):
                    asset_for_dw.setdefault("ip", meta.get("ip"))
            dark_web = await asyncio.wait_for(
                dark_web_correlator.correlate(target, asset_inventory=asset_for_dw, findings=synthetic_findings),
                timeout=120,
            )
            report["dark_web"] = dark_web
            if dark_web.get("risk_uplift"):
                report["risk_score"] = min(100, report["risk_score"] + dark_web["risk_uplift"])
        except Exception as e:
            report["errors"].append(f"dark_web_correlator: {e}")
            report["dark_web"] = None

        report["completed_at"] = datetime.now(timezone.utc).isoformat()
        report["summary"] = (
            f"{category.upper()} investigation of {target}: "
            f"{total_modules} modules | {total_entities} entities | "
            f"Risk: {report['risk_score']}/100 | "
            f"{critical} critical findings | {breach_count} breaches"
        )

        if progress_cb:
            await progress_cb({"phase": "complete", "message": report["summary"], "progress": 100, "total": 100})

        logger.info("Investigation complete", category=category, target=target, entities=total_entities, risk=report["risk_score"])
        return report

    async def _run_module(self, module, target: str, name: str, options: Dict = None) -> Optional[ModuleScanResult]:
        try:
            return await asyncio.wait_for(module.scan(target, options), timeout=60)
        except asyncio.TimeoutError:
            logger.warning(f"Module {name} timed out")
            return ModuleScanResult(module=name, target=target, success=False, error="Timeout after 60s")
        except Exception as e:
            logger.warning(f"Module {name} failed", error=str(e))
            return ModuleScanResult(module=name, target=target, success=False, error=str(e))


orchestrator = InvestigationOrchestrator()
