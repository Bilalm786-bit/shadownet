"""
ShadowNet — Dark Web: Threat Classifier
Keyword-based threat classification and IOC extraction engine.
No API keys required — works entirely offline with pattern matching.

Classifies dark web results into threat categories and auto-assigns severity.
Extracts IOCs: email addresses, BTC/ETH wallets, .onion URLs, IPs, hashes.
"""

import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


# ─── Threat Category Definitions ──────────────────────────
THREAT_CATEGORIES = {
    "credentials_leak": {
        "keywords": [
            "password", "passwd", "credentials", "login", "combo list",
            "combolist", "credential stuffing", "plaintext", "hash",
            "database dump", "db dump", "data dump", "leak", "leaked",
            "breach", "breached", "cracked", "dehashed", "dump",
        ],
        "severity": "critical",
        "description": "Credential or database leak",
    },
    "financial_fraud": {
        "keywords": [
            "credit card", "cc dump", "cvv", "fullz", "bank account",
            "carding", "skimmer", "atm", "paypal", "cashout", "money laundering",
            "western union", "wire transfer", "bitcoin mixer", "tumbler",
            "cryptocurrency", "wallet", "cash app",
        ],
        "severity": "critical",
        "description": "Financial fraud or stolen payment data",
    },
    "malware": {
        "keywords": [
            "malware", "ransomware", "trojan", "rat", "remote access",
            "keylogger", "botnet", "exploit", "zero-day", "0day",
            "payload", "backdoor", "rootkit", "crypter", "fud",
            "stealer", "infostealer", "loader", "dropper",
        ],
        "severity": "high",
        "description": "Malware, exploits, or hacking tools",
    },
    "pii_exposure": {
        "keywords": [
            "ssn", "social security", "passport", "driver license",
            "identity", "personal information", "dox", "doxxed",
            "full name", "address", "phone number", "date of birth",
            "medical record", "health record", "insurance",
        ],
        "severity": "critical",
        "description": "Personal identifiable information exposure",
    },
    "hacking_services": {
        "keywords": [
            "hacker for hire", "hack service", "ddos", "ddos attack",
            "booter", "stresser", "phishing kit", "social engineering",
            "account takeover", "brute force", "pentesting service",
            "hacking tutorial", "exploit kit",
        ],
        "severity": "high",
        "description": "Hacking services or attack tools",
    },
    "drugs_contraband": {
        "keywords": [
            "drugs", "narcotics", "cannabis", "cocaine", "heroin",
            "mdma", "lsd", "methamphetamine", "prescription",
            "pharmacy", "darknet market", "vendor", "escrow",
            "stealth shipping", "contraband", "weapons", "firearms",
        ],
        "severity": "medium",
        "description": "Drugs, contraband, or illegal marketplace",
    },
    "data_trading": {
        "keywords": [
            "database for sale", "selling data", "buy accounts",
            "accounts for sale", "email list", "leads", "bulk data",
            "scrape", "scraped", "harvested", "collection",
            "logs for sale", "stealer logs", "cloud logs",
        ],
        "severity": "high",
        "description": "Data trading or sale of stolen information",
    },
    "corporate_threat": {
        "keywords": [
            "corporate", "company", "employee", "internal", "proprietary",
            "trade secret", "confidential", "insider", "source code",
            "api key", "access token", "infrastructure", "vpn credentials",
        ],
        "severity": "critical",
        "description": "Corporate espionage or insider threats",
    },
}

# ─── IOC Extraction Patterns ────────────────────────────
IOC_PATTERNS = {
    "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    "btc_address": r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
    "eth_address": r'\b0x[a-fA-F0-9]{40}\b',
    "onion_url": r'https?://[a-z2-7]{16,56}\.onion[^\s"\'<>]*',
    "onion_v3": r'[a-z2-7]{56}\.onion',
    "ipv4": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    "md5_hash": r'\b[a-fA-F0-9]{32}\b',
    "sha256_hash": r'\b[a-fA-F0-9]{64}\b',
    "phone": r'\b\+?1?\d{10,14}\b',
}

# Common false positive IPs to ignore
IGNORE_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "192.168.1.1", "10.0.0.1"}


@dataclass
class ThreatResult:
    """Result of threat classification on a single item."""
    categories: List[str] = field(default_factory=list)
    severity: str = "info"  # critical, high, medium, low, info
    threat_score: float = 0.0  # 0.0 - 10.0
    matched_keywords: List[str] = field(default_factory=list)
    iocs: Dict[str, List[str]] = field(default_factory=dict)
    description: str = ""


class ThreatClassifier:
    """
    Classifies dark web content into threat categories and extracts IOCs.
    Fully offline — no API keys or external services needed.
    """

    SEVERITY_SCORES = {
        "critical": 9.0,
        "high": 7.0,
        "medium": 5.0,
        "low": 3.0,
        "info": 1.0,
    }

    def classify(self, text: str, url: str = "") -> ThreatResult:
        """
        Classify a piece of text/content into threat categories.
        Returns severity, matched categories, and extracted IOCs.
        """
        if not text:
            return ThreatResult(severity="info", threat_score=0.0)

        combined = f"{text} {url}".lower()
        matched_categories = []
        matched_keywords = []
        max_severity = "info"
        max_score = 0.0

        # Check each threat category
        for cat_name, cat_def in THREAT_CATEGORIES.items():
            cat_matches = []
            for keyword in cat_def["keywords"]:
                if keyword.lower() in combined:
                    cat_matches.append(keyword)

            if cat_matches:
                matched_categories.append(cat_name)
                matched_keywords.extend(cat_matches)

                cat_severity = cat_def["severity"]
                cat_score = self.SEVERITY_SCORES.get(cat_severity, 1.0)
                if cat_score > max_score:
                    max_score = cat_score
                    max_severity = cat_severity

        # Boost score based on number of category matches
        if len(matched_categories) > 1:
            max_score = min(10.0, max_score + len(matched_categories) * 0.5)

        # Check for .onion URL — always at least medium
        if ".onion" in combined and max_score < 5.0:
            max_score = 5.0
            if max_severity == "info":
                max_severity = "medium"

        # Extract IOCs
        iocs = self.extract_iocs(text + " " + url)

        # Boost score if IOCs found
        if iocs.get("btc_address") or iocs.get("eth_address"):
            max_score = min(10.0, max_score + 1.0)
        if iocs.get("onion_url") or iocs.get("onion_v3"):
            max_score = min(10.0, max_score + 0.5)

        # Generate description
        if matched_categories:
            cat_descriptions = [THREAT_CATEGORIES[c]["description"] for c in matched_categories]
            description = "; ".join(cat_descriptions[:3])
        else:
            description = "No specific threat indicators detected"

        return ThreatResult(
            categories=matched_categories,
            severity=max_severity,
            threat_score=round(max_score, 1),
            matched_keywords=list(set(matched_keywords))[:20],
            iocs=iocs,
            description=description,
        )

    def extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """Extract Indicators of Compromise from text."""
        iocs = {}
        for ioc_type, pattern in IOC_PATTERNS.items():
            matches = list(set(re.findall(pattern, text)))
            # Filter false positives
            if ioc_type == "ipv4":
                matches = [ip for ip in matches if ip not in IGNORE_IPS]
            if ioc_type == "md5_hash":
                # Avoid matching things that are clearly not hashes (too common hex)
                matches = [h for h in matches if not h.startswith("00000")]
            if matches:
                iocs[ioc_type] = matches[:20]  # Cap at 20 per type
        return iocs

    def classify_batch(self, items: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """
        Classify a batch of results. Each item should have 'title', 'description', 'url'.
        Returns the items with added threat classification fields.
        """
        classified = []
        for item in items:
            text = f"{item.get('title', '')} {item.get('description', '')} {item.get('url', '')}"
            result = self.classify(text, item.get("url", ""))
            classified.append({
                **item,
                "threat_categories": result.categories,
                "severity": result.severity,
                "threat_score": result.threat_score,
                "matched_keywords": result.matched_keywords,
                "iocs": result.iocs,
                "threat_description": result.description,
            })
        return classified

    def calculate_overall_risk(self, classified_results: List[Dict]) -> Dict[str, Any]:
        """
        Calculate an overall risk assessment for a set of classified results.
        Returns risk score, category breakdown, and IOC summary.
        """
        if not classified_results:
            return {
                "risk_score": 0.0,
                "risk_level": "none",
                "category_breakdown": {},
                "total_iocs": 0,
                "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            }

        # Severity counts
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        category_counts: Dict[str, int] = {}
        all_iocs: Dict[str, set] = {}
        scores = []

        for item in classified_results:
            sev = item.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            scores.append(item.get("threat_score", 0.0))

            for cat in item.get("threat_categories", []):
                category_counts[cat] = category_counts.get(cat, 0) + 1

            for ioc_type, ioc_values in item.get("iocs", {}).items():
                if ioc_type not in all_iocs:
                    all_iocs[ioc_type] = set()
                all_iocs[ioc_type].update(ioc_values)

        # Overall risk = weighted average with emphasis on max
        avg_score = sum(scores) / len(scores) if scores else 0
        max_score = max(scores) if scores else 0
        risk_score = round((avg_score * 0.4 + max_score * 0.6), 1)
        risk_score = min(10.0, risk_score)

        # Risk level
        if risk_score >= 8.0:
            risk_level = "critical"
        elif risk_score >= 6.0:
            risk_level = "high"
        elif risk_score >= 4.0:
            risk_level = "medium"
        elif risk_score >= 2.0:
            risk_level = "low"
        else:
            risk_level = "info"

        total_iocs = sum(len(v) for v in all_iocs.values())
        ioc_summary = {k: list(v)[:10] for k, v in all_iocs.items()}

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "category_breakdown": category_counts,
            "severity_counts": severity_counts,
            "total_iocs": total_iocs,
            "ioc_summary": ioc_summary,
        }


# Singleton
threat_classifier = ThreatClassifier()
