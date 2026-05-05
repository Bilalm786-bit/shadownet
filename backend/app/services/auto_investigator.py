"""
ShadowNet — Auto-Investigator Service
One-click complete investigation engine.
Input: any target string → Output: complete intelligence dossier.
Auto-detects target type, runs all relevant modules, chains findings,
and generates a comprehensive AI-powered report.
"""

import re
import asyncio
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from app.modules.base import ModuleRegistry, ScanResult as ModuleScanResult
from app.services.ai_analyst import ai_analyst
import structlog

logger = structlog.get_logger(__name__)

# Target type detection patterns
TARGET_PATTERNS = {
    "email": re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
    "ip": re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'),
    "phone": re.compile(r'^[\+]?[0-9]{10,15}$'),
    "domain": re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'),
    "url": re.compile(r'^https?://'),
    "username": re.compile(r'^[a-zA-Z0-9._-]{3,30}$'),
}

# Target type → modules to run
TYPE_MODULE_MAP = {
    "email": [
        "identity.email_validator",
        "breach.breach_checker",
        "breach.paste_monitor",
        "breach.google_dorker",
        "identity.social_analyzer",
    ],
    "domain": [
        "network.dns_recon",
        "network.whois_lookup",
        "network.subdomain_enum",
        "network.ssl_analyzer",
        "network.port_scanner",
        "network.tech_detector",
        "network.web_crawler",
        "network.shodan_free",
        "network.wayback_machine",
        "breach.google_dorker",
        "breach.breach_checker",
    ],
    "ip": [
        "network.ip_geolocation",
        "network.port_scanner",
        "network.shodan_free",
        "breach.google_dorker",
    ],
    "username": [
        "identity.username_lookup",
        "identity.social_analyzer",
        "breach.breach_checker",
        "breach.paste_monitor",
        "breach.google_dorker",
        "socmint.github_recon",
    ],
    "phone": [
        "identity.phone_lookup",
        "breach.google_dorker",
    ],
    "url": [
        "network.tech_detector",
        "network.web_crawler",
        "breach.google_dorker",
    ],
    "person": [
        "identity.username_lookup",
        "identity.social_analyzer",
        "breach.google_dorker",
    ],
}

# Chain rules: when a module finds certain entities, trigger follow-up scans
CHAIN_RULES = {
    "domain": {
        # If DNS/subdomain finds IPs → scan ports + shodan
        "ip": ["network.port_scanner", "network.shodan_free", "network.ip_geolocation"],
        # If subdomain found → SSL + tech detect
        "subdomain": ["network.ssl_analyzer", "network.tech_detector"],
    },
    "email": {
        # If breach found with domain → scan that domain
        "domain": ["network.dns_recon", "network.whois_lookup"],
        # If username found → social analysis
        "username": ["identity.social_analyzer"],
    },
    "username": {
        # If email found → breach check it
        "email": ["breach.breach_checker"],
    },
}


class AutoInvestigator:
    """Full auto-investigation engine — one input, complete intelligence dossier."""

    @staticmethod
    def detect_target_type(target: str) -> str:
        """Auto-detect the type of a target string."""
        target = target.strip()

        # Check patterns in priority order
        if TARGET_PATTERNS["email"].match(target):
            return "email"
        if TARGET_PATTERNS["ip"].match(target):
            return "ip"
        if TARGET_PATTERNS["url"].match(target):
            return "url"
        if TARGET_PATTERNS["phone"].match(target.replace(" ", "").replace("-", "")):
            return "phone"
        if TARGET_PATTERNS["domain"].match(target):
            return "domain"
        # Default: username
        return "username"

    @staticmethod
    async def investigate(
        target: str,
        target_type: str = None,
        depth: int = 1,
        progress_callback=None,
    ) -> Dict[str, Any]:
        """
        Run a full auto-investigation.
        
        Args:
            target: The target string (email, domain, IP, username, etc.)
            target_type: Override auto-detection
            depth: How deep to chain findings (1 = no chaining, 2 = one level)
            progress_callback: async callable for progress updates
            
        Returns:
            Complete investigation report
        """
        target = target.strip()
        if not target_type:
            target_type = AutoInvestigator.detect_target_type(target)

        logger.info("Auto-investigation starting", target=target, type=target_type, depth=depth)

        report = {
            "target": target,
            "target_type": target_type,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "modules_run": [],
            "results": {},
            "entities_found": [],
            "chain_results": {},
            "ai_analysis": None,
            "risk_score": 0,
            "summary": "",
            "errors": [],
        }

        # Get modules for this target type
        modules_to_run = TYPE_MODULE_MAP.get(target_type, [])
        # Filter to only registered modules
        available = [m for m in modules_to_run if ModuleRegistry.get(m)]

        if not available:
            report["errors"].append(f"No modules available for target type '{target_type}'")
            report["summary"] = f"Investigation failed: no modules for type '{target_type}'"
            return report

        # Phase 1: Run all primary modules
        if progress_callback:
            await progress_callback({
                "phase": "primary_scan",
                "message": f"Running {len(available)} modules against {target}",
                "progress": 0,
                "total": len(available),
            })

        primary_results = []
        for i, module_name in enumerate(available):
            module = ModuleRegistry.get(module_name)
            if not module:
                continue

            try:
                if progress_callback:
                    await progress_callback({
                        "phase": "primary_scan",
                        "message": f"Running {module_name}...",
                        "progress": i + 1,
                        "total": len(available),
                        "module": module_name,
                    })

                result = await module.scan(target)
                primary_results.append(result)
                report["modules_run"].append(module_name)
                report["results"][module_name] = {
                    "success": result.success,
                    "summary": result.summary,
                    "severity": result.severity,
                    "entity_count": len(result.entities),
                    "data": result.raw_data,
                }

                # Collect entities
                for entity in result.entities:
                    report["entities_found"].append({
                        "type": entity.entity_type,
                        "value": entity.value,
                        "source": entity.source,
                        "confidence": entity.confidence,
                        "metadata": entity.metadata,
                    })

            except Exception as e:
                logger.warning(f"Module {module_name} failed", error=str(e))
                report["errors"].append(f"{module_name}: {str(e)}")

        # Phase 2: Chain findings (if depth > 1)
        if depth > 1:
            chain_rules = CHAIN_RULES.get(target_type, {})
            if chain_rules and progress_callback:
                await progress_callback({
                    "phase": "chaining",
                    "message": "Chaining findings for deeper investigation...",
                })

            chained_targets = set()
            for entity_info in report["entities_found"]:
                etype = entity_info["type"]
                evalue = entity_info["value"]
                chain_modules = chain_rules.get(etype, [])

                if chain_modules and evalue != target and evalue not in chained_targets:
                    chained_targets.add(evalue)
                    for chain_mod in chain_modules[:2]:  # Limit chaining
                        mod = ModuleRegistry.get(chain_mod)
                        if mod and evalue not in chained_targets:
                            try:
                                chain_result = await mod.scan(evalue)
                                chain_key = f"{chain_mod}:{evalue}"
                                report["chain_results"][chain_key] = {
                                    "success": chain_result.success,
                                    "summary": chain_result.summary,
                                    "entity_count": len(chain_result.entities),
                                }
                                report["modules_run"].append(f"[chain] {chain_mod}")
                            except Exception as e:
                                report["errors"].append(f"Chain {chain_mod}:{evalue}: {str(e)}")
                        if len(chained_targets) > 5:
                            break

        # Phase 3: AI Analysis
        if progress_callback:
            await progress_callback({
                "phase": "ai_analysis",
                "message": "Running AI threat analysis...",
            })

        if ai_analyst.client:
            try:
                scan_data = [
                    {"module": r.module, "summary": r.summary, "data": r.raw_data}
                    for r in primary_results if r.success
                ]
                analysis = await ai_analyst.analyze_scan_results(target, scan_data)
                report["ai_analysis"] = analysis.get("analysis")
                if analysis.get("analysis", {}).get("risk_score"):
                    report["risk_score"] = analysis["analysis"]["risk_score"]
            except Exception as e:
                report["errors"].append(f"AI analysis: {str(e)}")
        else:
            # Generate a basic risk score without AI
            severity_scores = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}
            risk = 0
            for result in primary_results:
                risk += severity_scores.get(result.severity, 0)
            report["risk_score"] = min(risk, 100)

        # Build summary
        total_entities = len(report["entities_found"])
        total_modules = len(report["modules_run"])
        critical_findings = sum(1 for r in primary_results if r.severity in ("critical", "high"))

        report["completed_at"] = datetime.now(timezone.utc).isoformat()
        report["summary"] = (
            f"Investigation of {target} ({target_type}): "
            f"{total_modules} modules run | {total_entities} entities discovered | "
            f"Risk Score: {report['risk_score']}/100 | "
            f"{critical_findings} critical/high findings"
        )

        if progress_callback:
            await progress_callback({
                "phase": "complete",
                "message": report["summary"],
                "progress": 100,
                "total": 100,
            })

        logger.info("Auto-investigation complete", target=target, entities=total_entities, risk=report["risk_score"])
        return report


# Singleton
auto_investigator = AutoInvestigator()
