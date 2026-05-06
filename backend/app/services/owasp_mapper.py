"""
ShadowNet — OWASP Top 10 (2021) Mapper

Maps a finding's CWE / plugin family to the OWASP Top 10 (2021) category, with
official titles, descriptions, and reference URLs. Provides a flat category
table the frontend can render as a radar chart and coverage matrix.

Reference: https://owasp.org/www-project-top-ten/
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


OWASP_TOP_10_2021: Dict[str, Dict[str, str]] = {
    "A01": {
        "code": "A01",
        "id": "A01:2021",
        "title": "Broken Access Control",
        "description": "Restrictions on what authenticated users are allowed to do are often not properly enforced.",
        "reference": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    },
    "A02": {
        "code": "A02",
        "id": "A02:2021",
        "title": "Cryptographic Failures",
        "description": "Failures related to cryptography (or lack thereof) often lead to sensitive data exposure.",
        "reference": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    },
    "A03": {
        "code": "A03",
        "id": "A03:2021",
        "title": "Injection",
        "description": "Injection flaws (SQL, NoSQL, LDAP, OS command, XSS, …) occur when untrusted data is sent to an interpreter.",
        "reference": "https://owasp.org/Top10/A03_2021-Injection/",
    },
    "A04": {
        "code": "A04",
        "id": "A04:2021",
        "title": "Insecure Design",
        "description": "Risks related to design and architectural flaws — distinct from implementation bugs.",
        "reference": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
    },
    "A05": {
        "code": "A05",
        "id": "A05:2021",
        "title": "Security Misconfiguration",
        "description": "Missing security hardening, default accounts, verbose error messages, unnecessary features.",
        "reference": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    },
    "A06": {
        "code": "A06",
        "id": "A06:2021",
        "title": "Vulnerable and Outdated Components",
        "description": "Using libraries / frameworks / OS components with known vulnerabilities.",
        "reference": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    },
    "A07": {
        "code": "A07",
        "id": "A07:2021",
        "title": "Identification and Authentication Failures",
        "description": "Confirmation of user identity, authentication, and session management is often broken.",
        "reference": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    },
    "A08": {
        "code": "A08",
        "id": "A08:2021",
        "title": "Software and Data Integrity Failures",
        "description": "Code / infra updates without verifying integrity (CI/CD pipelines, deserialization, plugins).",
        "reference": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
    },
    "A09": {
        "code": "A09",
        "id": "A09:2021",
        "title": "Security Logging and Monitoring Failures",
        "description": "Insufficient logging, detection, monitoring and active response to attacks.",
        "reference": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
    },
    "A10": {
        "code": "A10",
        "id": "A10:2021",
        "title": "Server-Side Request Forgery (SSRF)",
        "description": "Server-side resources fetched on attacker-controlled URLs (cloud metadata, internal services, file://).",
        "reference": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
    },
}


CWE_TO_OWASP: Dict[str, str] = {
    "CWE-22": "A01",     # Path Traversal
    "CWE-23": "A01",
    "CWE-35": "A01",
    "CWE-59": "A01",
    "CWE-200": "A01",    # Information Exposure
    "CWE-201": "A01",
    "CWE-219": "A01",
    "CWE-264": "A01",
    "CWE-275": "A01",
    "CWE-276": "A01",
    "CWE-284": "A01",
    "CWE-285": "A01",
    "CWE-352": "A01",
    "CWE-359": "A01",
    "CWE-377": "A01",
    "CWE-402": "A01",
    "CWE-425": "A01",
    "CWE-441": "A01",
    "CWE-538": "A01",
    "CWE-540": "A01",
    "CWE-552": "A01",
    "CWE-566": "A01",
    "CWE-601": "A01",    # Open redirect
    "CWE-639": "A01",
    "CWE-651": "A01",
    "CWE-668": "A01",
    "CWE-706": "A01",
    "CWE-862": "A01",
    "CWE-863": "A01",
    "CWE-913": "A01",
    "CWE-922": "A01",
    "CWE-1275": "A01",

    "CWE-261": "A02",
    "CWE-296": "A02",
    "CWE-310": "A02",    # Cryptographic issues
    "CWE-319": "A02",    # Cleartext transmission
    "CWE-321": "A02",
    "CWE-322": "A02",
    "CWE-323": "A02",
    "CWE-324": "A02",
    "CWE-325": "A02",
    "CWE-326": "A02",    # Inadequate encryption
    "CWE-327": "A02",    # Broken crypto algorithm
    "CWE-328": "A02",
    "CWE-329": "A02",
    "CWE-330": "A02",    # Use of insufficiently random values
    "CWE-331": "A02",
    "CWE-335": "A02",
    "CWE-336": "A02",
    "CWE-337": "A02",
    "CWE-338": "A02",
    "CWE-340": "A02",
    "CWE-347": "A02",    # Improper verification of cryptographic signature (JWT)
    "CWE-523": "A02",
    "CWE-720": "A02",
    "CWE-757": "A02",
    "CWE-759": "A02",
    "CWE-760": "A02",
    "CWE-780": "A02",
    "CWE-818": "A02",
    "CWE-916": "A02",

    "CWE-20": "A03",     # Improper input validation
    "CWE-74": "A03",
    "CWE-75": "A03",
    "CWE-77": "A03",
    "CWE-78": "A03",     # OS command injection
    "CWE-79": "A03",     # XSS
    "CWE-80": "A03",
    "CWE-83": "A03",
    "CWE-87": "A03",
    "CWE-88": "A03",
    "CWE-89": "A03",     # SQL injection
    "CWE-90": "A03",     # LDAP injection
    "CWE-91": "A03",     # XML injection
    "CWE-93": "A03",
    "CWE-94": "A03",     # Code injection
    "CWE-95": "A03",
    "CWE-96": "A03",
    "CWE-97": "A03",
    "CWE-98": "A03",
    "CWE-99": "A03",
    "CWE-100": "A03",
    "CWE-113": "A03",    # HTTP response splitting
    "CWE-116": "A03",
    "CWE-138": "A03",
    "CWE-184": "A03",
    "CWE-470": "A03",
    "CWE-471": "A03",
    "CWE-564": "A03",
    "CWE-610": "A03",    # Externally controlled reference
    "CWE-643": "A03",
    "CWE-644": "A03",
    "CWE-652": "A03",
    "CWE-917": "A03",    # Expression language injection (SSTI)

    "CWE-73": "A04",
    "CWE-183": "A04",
    "CWE-209": "A04",
    "CWE-213": "A04",
    "CWE-235": "A04",
    "CWE-256": "A04",
    "CWE-257": "A04",
    "CWE-266": "A04",
    "CWE-269": "A04",
    "CWE-280": "A04",
    "CWE-311": "A04",
    "CWE-312": "A04",
    "CWE-313": "A04",
    "CWE-316": "A04",
    "CWE-419": "A04",
    "CWE-430": "A04",
    "CWE-434": "A04",
    "CWE-444": "A04",
    "CWE-451": "A04",
    "CWE-472": "A04",
    "CWE-501": "A04",
    "CWE-522": "A04",
    "CWE-525": "A04",
    "CWE-539": "A04",
    "CWE-579": "A04",
    "CWE-598": "A04",
    "CWE-602": "A04",
    "CWE-642": "A04",
    "CWE-646": "A04",
    "CWE-650": "A04",    # Trusting HTTP method (TRACE / PUT)
    "CWE-653": "A04",
    "CWE-656": "A04",
    "CWE-657": "A04",
    "CWE-799": "A04",
    "CWE-807": "A04",
    "CWE-840": "A04",
    "CWE-841": "A04",
    "CWE-927": "A04",
    "CWE-1021": "A04",
    "CWE-1173": "A04",

    "CWE-2": "A05",
    "CWE-11": "A05",
    "CWE-13": "A05",
    "CWE-15": "A05",
    "CWE-16": "A05",     # Configuration
    "CWE-260": "A05",
    "CWE-315": "A05",
    "CWE-520": "A05",
    "CWE-526": "A05",
    "CWE-537": "A05",
    "CWE-541": "A05",
    "CWE-547": "A05",
    "CWE-611": "A05",    # XXE
    "CWE-614": "A05",    # Sensitive cookie without Secure flag
    "CWE-756": "A05",
    "CWE-776": "A05",
    "CWE-942": "A05",    # CORS misconfiguration
    "CWE-1004": "A05",   # Sensitive cookie without HttpOnly
    "CWE-1032": "A05",
    "CWE-1174": "A05",
    "CWE-693": "A05",    # Protection mechanism failure (security headers)

    "CWE-937": "A06",
    "CWE-1035": "A06",
    "CWE-1104": "A06",   # Use of unmaintained third-party components

    "CWE-255": "A07",
    "CWE-259": "A07",    # Use of hard-coded password
    "CWE-287": "A07",    # Improper authentication
    "CWE-288": "A07",
    "CWE-290": "A07",    # Authentication bypass
    "CWE-294": "A07",
    "CWE-295": "A07",    # Improper certificate validation
    "CWE-297": "A07",
    "CWE-300": "A07",
    "CWE-302": "A07",
    "CWE-304": "A07",
    "CWE-306": "A07",    # Missing authentication for critical function
    "CWE-307": "A07",    # Improper restriction of excessive auth attempts
    "CWE-346": "A07",
    "CWE-384": "A07",    # Session fixation
    "CWE-521": "A07",    # Weak password requirements
    "CWE-613": "A07",
    "CWE-620": "A07",
    "CWE-640": "A07",
    "CWE-798": "A07",    # Use of hard-coded credentials
    "CWE-940": "A07",
    "CWE-1216": "A07",

    "CWE-345": "A08",
    "CWE-353": "A08",
    "CWE-426": "A08",
    "CWE-494": "A08",
    "CWE-502": "A08",    # Deserialization of untrusted data
    "CWE-565": "A08",
    "CWE-784": "A08",
    "CWE-829": "A08",
    "CWE-830": "A08",
    "CWE-915": "A08",

    "CWE-117": "A09",
    "CWE-223": "A09",
    "CWE-532": "A09",
    "CWE-778": "A09",

    "CWE-918": "A10",    # SSRF
}


PLUGIN_FAMILY_TO_OWASP: Dict[str, str] = {
    "TLS / SSL": "A02",
    "HTTP Security Headers": "A05",
    "Sensitive File Disclosure": "A01",
    "Information Disclosure": "A01",
    "Cloud Storage": "A01",
    "Subdomain Takeover": "A01",
    "CORS Misconfiguration": "A05",
    "Open Redirect": "A01",
    "Reflected XSS Pre-condition": "A03",
    "SQL Injection": "A03",
    "SSRF": "A10",
    "Server-Side Template Injection": "A03",
    "XML External Entity": "A05",
    "GraphQL Misconfiguration": "A05",
    "Authentication / Default Credentials": "A07",
    "Authentication Bypass": "A07",
    "JWT / Authentication": "A02",
    "Session / Cookie Security": "A05",
    "Host Header Injection": "A04",
    "HTTP Methods": "A04",
    "DNS / Email Authentication": "A07",
    "Secret Disclosure (Public VCS)": "A07",
    "Secret Disclosure (Code)": "A07",
    "Sensitive Data Exposure": "A02",
    "Network Services": "A05",
    "WAF Detection": "A05",
    "CMS Enumeration": "A05",
    "Application Surface": "A04",
    "Web Crawler": "A05",
    "Edge / CDN": "A05",
    "Subdomain Enumeration": "A05",
    "Virtual Hosts": "A05",
    "DNS": "A05",
    "Network": "A05",
    "Technology Stack": "A06",
    "HTTP Fingerprint": "A05",
}


def map_finding(cwe: Optional[str], family: Optional[str] = None) -> Optional[str]:
    """Return OWASP code (A01..A10) for a finding, or None."""
    if cwe:
        normalized = cwe.upper().strip()
        if normalized in CWE_TO_OWASP:
            return CWE_TO_OWASP[normalized]
        if normalized.startswith("CWE-"):
            num = normalized[4:].split(".")[0]
            for variant in (f"CWE-{num}",):
                if variant in CWE_TO_OWASP:
                    return CWE_TO_OWASP[variant]
    if family and family in PLUGIN_FAMILY_TO_OWASP:
        return PLUGIN_FAMILY_TO_OWASP[family]
    return None


def get_category(code: Optional[str]) -> Optional[Dict[str, str]]:
    if not code:
        return None
    return OWASP_TOP_10_2021.get(code)


def annotate_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Mutate a finding dict in-place to add `owasp` field with full category info."""
    code = map_finding(finding.get("cwe"), finding.get("family"))
    if code:
        cat = OWASP_TOP_10_2021[code]
        finding["owasp"] = {
            "code": cat["code"],
            "id": cat["id"],
            "title": cat["title"],
            "reference": cat["reference"],
        }
    return finding


def coverage_matrix(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return [{code, id, title, count, severity_max}] for all 10 OWASP categories."""
    SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    by_code: Dict[str, Dict[str, Any]] = {}
    for code, meta in OWASP_TOP_10_2021.items():
        by_code[code] = {
            **meta,
            "count": 0,
            "severity_max": "info",
            "severity_rank": 0,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        }

    for f in findings:
        owasp = f.get("owasp") or {}
        code = owasp.get("code") or map_finding(f.get("cwe"), f.get("family"))
        if not code or code not in by_code:
            continue
        bucket = by_code[code]
        bucket["count"] += 1
        sev = f.get("severity", "info")
        bucket["by_severity"][sev] = bucket["by_severity"].get(sev, 0) + 1
        rank = SEVERITY_RANK.get(sev, 0)
        if rank > bucket["severity_rank"]:
            bucket["severity_rank"] = rank
            bucket["severity_max"] = sev

    return [by_code[c] for c in sorted(by_code.keys())]


def summary_stats(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    coverage = coverage_matrix(findings)
    covered = [c for c in coverage if c["count"] > 0]
    return {
        "categories": coverage,
        "categories_covered": len(covered),
        "categories_total": 10,
        "highest_risk_categories": sorted(
            covered, key=lambda c: (-c["severity_rank"], -c["count"])
        )[:3],
    }
