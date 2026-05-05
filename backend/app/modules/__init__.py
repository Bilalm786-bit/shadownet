# ShadowNet — OSINT Modules Package
# Import all modules to trigger auto-registration with ModuleRegistry
# Each import is wrapped in try/except so missing deps don't break the app

import structlog
logger = structlog.get_logger(__name__)

# ─── Identity Modules ──────────────────────────────────────
try:
    from app.modules.identity.username_lookup import UsernameLookup
    logger.info("[+] Module loaded: identity.username_lookup")
except Exception as e:
    logger.warning("[-] Failed to load identity.username_lookup", error=str(e))

try:
    from app.modules.identity.email_validator import EmailValidator
    logger.info("[+] Module loaded: identity.email_validator")
except Exception as e:
    logger.warning("[-] Failed to load identity.email_validator", error=str(e))

try:
    from app.modules.identity.phone_lookup import PhoneLookup
    logger.info("[+] Module loaded: identity.phone_lookup")
except Exception as e:
    logger.warning("[-] Failed to load identity.phone_lookup", error=str(e))

try:
    from app.modules.identity.social_analyzer import SocialAnalyzer
    logger.info("[+] Module loaded: identity.social_analyzer")
except Exception as e:
    logger.warning("[-] Failed to load identity.social_analyzer", error=str(e))

try:
    from app.modules.identity.social_media_scraper import StealthSocialScraper
    logger.info("[+] Module loaded: identity.social_scraper")
except Exception as e:
    logger.warning("[-] Failed to load identity.social_scraper", error=str(e))

try:
    from app.modules.identity.cnic_lookup import CNICLookup
    logger.info("[+] Module loaded: identity.cnic_lookup")
except Exception as e:
    logger.warning("[-] Failed to load identity.cnic_lookup", error=str(e))

try:
    from app.modules.identity.whois_person import WhoisPersonLookup
    logger.info("[+] Module loaded: identity.whois_person")
except Exception as e:
    logger.warning("[-] Failed to load identity.whois_person", error=str(e))

try:
    from app.modules.identity.reverse_image import ReverseImageSearch
    logger.info("[+] Module loaded: identity.reverse_image")
except Exception as e:
    logger.warning("[-] Failed to load identity.reverse_image", error=str(e))

try:
    from app.modules.identity.stealth_browser import StealthBrowser
    logger.info("[+] Module loaded: identity.stealth_browser")
except Exception as e:
    logger.warning("[-] Failed to load identity.stealth_browser", error=str(e))

# ─── Network Modules ───────────────────────────────────────
try:
    from app.modules.network.dns_recon import DNSRecon
    logger.info("[+] Module loaded: network.dns_recon")
except Exception as e:
    logger.warning("[-] Failed to load network.dns_recon", error=str(e))

try:
    from app.modules.network.whois_lookup import WhoisLookup
    logger.info("[+] Module loaded: network.whois_lookup")
except Exception as e:
    logger.warning("[-] Failed to load network.whois_lookup", error=str(e))

try:
    from app.modules.network.ip_geolocation import IPGeolocation
    logger.info("[+] Module loaded: network.ip_geolocation")
except Exception as e:
    logger.warning("[-] Failed to load network.ip_geolocation", error=str(e))

try:
    from app.modules.network.subdomain_enum import SubdomainEnum
    logger.info("[+] Module loaded: network.subdomain_enum")
except Exception as e:
    logger.warning("[-] Failed to load network.subdomain_enum", error=str(e))

try:
    from app.modules.network.wayback_machine import WaybackMachine
    logger.info("[+] Module loaded: network.wayback_machine")
except Exception as e:
    logger.warning("[-] Failed to load network.wayback_machine", error=str(e))

try:
    from app.modules.network.port_scanner import PortScanner
    logger.info("[+] Module loaded: network.port_scanner")
except Exception as e:
    logger.warning("[-] Failed to load network.port_scanner", error=str(e))

try:
    from app.modules.network.ssl_analyzer import SSLAnalyzer
    logger.info("[+] Module loaded: network.ssl_analyzer")
except Exception as e:
    logger.warning("[-] Failed to load network.ssl_analyzer", error=str(e))

try:
    from app.modules.network.tech_detector import TechDetector
    logger.info("[+] Module loaded: network.tech_detector")
except Exception as e:
    logger.warning("[-] Failed to load network.tech_detector", error=str(e))

try:
    from app.modules.network.web_crawler import WebCrawler
    logger.info("[+] Module loaded: network.web_crawler")
except Exception as e:
    logger.warning("[-] Failed to load network.web_crawler", error=str(e))

try:
    from app.modules.network.shodan_free import ShodanFree
    logger.info("[+] Module loaded: network.shodan_free")
except Exception as e:
    logger.warning("[-] Failed to load network.shodan_free", error=str(e))

# ─── NEW: VirusTotal Scanner ──────────────────────────────
try:
    from app.modules.network.virustotal_scanner import VirusTotalScanner
    logger.info("[+] Module loaded: network.virustotal")
except Exception as e:
    logger.warning("[-] Failed to load network.virustotal", error=str(e))

# ─── NEW: Censys Scanner ─────────────────────────────────
try:
    from app.modules.network.censys_scanner import CensysScanner
    logger.info("[+] Module loaded: network.censys")
except Exception as e:
    logger.warning("[-] Failed to load network.censys", error=str(e))

# ─── Breach / OSINT Modules ────────────────────────────────
try:
    from app.modules.breach.breach_checker import BreachChecker
    logger.info("[+] Module loaded: breach.breach_checker")
except Exception as e:
    logger.warning("[-] Failed to load breach.breach_checker", error=str(e))

try:
    from app.modules.breach.google_dorker import GoogleDorker
    logger.info("[+] Module loaded: breach.google_dorker")
except Exception as e:
    logger.warning("[-] Failed to load breach.google_dorker", error=str(e))

try:
    from app.modules.breach.paste_monitor import PasteMonitor
    logger.info("[+] Module loaded: breach.paste_monitor")
except Exception as e:
    logger.warning("[-] Failed to load breach.paste_monitor", error=str(e))

# ─── NEW: Google Search Intelligence ─────────────────────
try:
    from app.modules.breach.google_search_module import GoogleSearchModule
    logger.info("[+] Module loaded: breach.google_search")
except Exception as e:
    logger.warning("[-] Failed to load breach.google_search", error=str(e))

# ─── NEW: Tavily AI Search ───────────────────────────────
try:
    from app.modules.breach.tavily_search import TavilySearch
    logger.info("[+] Module loaded: breach.tavily_search")
except Exception as e:
    logger.warning("[-] Failed to load breach.tavily_search", error=str(e))

# ─── NEW: Stealth Scraper ────────────────────────────────
try:
    from app.modules.breach.stealth_scraper import StealthScraper
    logger.info("[+] Module loaded: breach.stealth_scraper")
except Exception as e:
    logger.warning("[-] Failed to load breach.stealth_scraper", error=str(e))

# ─── Document Modules ──────────────────────────────────────
try:
    from app.modules.document.metadata_extractor import DocumentOSINT
    logger.info("[+] Module loaded: document.metadata_extractor")
except Exception as e:
    logger.warning("[-] Failed to load document.metadata_extractor", error=str(e))

# ─── SOCMINT Modules ───────────────────────────────────────
try:
    from app.modules.socmint.github_recon import GitHubRecon
    logger.info("[+] Module loaded: socmint.github_recon")
except Exception as e:
    logger.warning("[-] Failed to load socmint.github_recon", error=str(e))

# ─── Threat Intel Modules ──────────────────────────────────
try:
    from app.modules.threat.threat_intel_lookup import ThreatIntelLookup
    logger.info("[+] Module loaded: threat.intel_lookup")
except Exception as e:
    logger.warning("[-] Failed to load threat.intel_lookup", error=str(e))

# ─── Recon Modules (passive) ────────────────────────────
try:
    from app.modules.recon.asn_lookup import ASNLookup
    logger.info("[+] Module loaded: recon.asn_lookup")
except Exception as e:
    logger.warning("[-] Failed to load recon.asn_lookup", error=str(e))

try:
    from app.modules.recon.cdn_detector import CDNDetector
    logger.info("[+] Module loaded: recon.cdn_detector")
except Exception as e:
    logger.warning("[-] Failed to load recon.cdn_detector", error=str(e))

try:
    from app.modules.recon.reverse_ip import ReverseIPLookup
    logger.info("[+] Module loaded: recon.reverse_ip")
except Exception as e:
    logger.warning("[-] Failed to load recon.reverse_ip", error=str(e))

try:
    from app.modules.recon.http_fingerprint import HTTPFingerprint
    logger.info("[+] Module loaded: recon.http_fingerprint")
except Exception as e:
    logger.warning("[-] Failed to load recon.http_fingerprint", error=str(e))

try:
    from app.modules.recon.robots_sitemap import RobotsSitemapAnalyzer
    logger.info("[+] Module loaded: recon.robots_sitemap")
except Exception as e:
    logger.warning("[-] Failed to load recon.robots_sitemap", error=str(e))

# ─── Enumeration Modules (active, low-impact) ──────────
try:
    from app.modules.enumeration.directory_buster import DirectoryBuster
    logger.info("[+] Module loaded: enumeration.directory_buster")
except Exception as e:
    logger.warning("[-] Failed to load enumeration.directory_buster", error=str(e))

try:
    from app.modules.enumeration.vhost_enum import VhostEnum
    logger.info("[+] Module loaded: enumeration.vhost_enum")
except Exception as e:
    logger.warning("[-] Failed to load enumeration.vhost_enum", error=str(e))

try:
    from app.modules.enumeration.parameter_finder import ParameterFinder
    logger.info("[+] Module loaded: enumeration.parameter_finder")
except Exception as e:
    logger.warning("[-] Failed to load enumeration.parameter_finder", error=str(e))

try:
    from app.modules.enumeration.js_endpoint_extractor import JSEndpointExtractor
    logger.info("[+] Module loaded: enumeration.js_endpoints")
except Exception as e:
    logger.warning("[-] Failed to load enumeration.js_endpoints", error=str(e))

try:
    from app.modules.enumeration.cms_enum import CMSEnum
    logger.info("[+] Module loaded: enumeration.cms_enum")
except Exception as e:
    logger.warning("[-] Failed to load enumeration.cms_enum", error=str(e))

try:
    from app.modules.enumeration.s3_bucket_finder import S3BucketFinder
    logger.info("[+] Module loaded: enumeration.s3_buckets")
except Exception as e:
    logger.warning("[-] Failed to load enumeration.s3_buckets", error=str(e))

# ─── Exploitation / Vulnerability Modules ──────────────
try:
    from app.modules.exploit.security_headers import SecurityHeaders
    logger.info("[+] Module loaded: exploit.security_headers")
except Exception as e:
    logger.warning("[-] Failed to load exploit.security_headers", error=str(e))

try:
    from app.modules.exploit.cve_matcher import CVEMatcher
    logger.info("[+] Module loaded: exploit.cve_matcher")
except Exception as e:
    logger.warning("[-] Failed to load exploit.cve_matcher", error=str(e))

try:
    from app.modules.exploit.subdomain_takeover import SubdomainTakeover
    logger.info("[+] Module loaded: exploit.subdomain_takeover")
except Exception as e:
    logger.warning("[-] Failed to load exploit.subdomain_takeover", error=str(e))

try:
    from app.modules.exploit.cors_misconfig import CORSMisconfig
    logger.info("[+] Module loaded: exploit.cors_misconfig")
except Exception as e:
    logger.warning("[-] Failed to load exploit.cors_misconfig", error=str(e))

try:
    from app.modules.exploit.open_redirect import OpenRedirect
    logger.info("[+] Module loaded: exploit.open_redirect")
except Exception as e:
    logger.warning("[-] Failed to load exploit.open_redirect", error=str(e))

try:
    from app.modules.exploit.reflection_probe import ReflectionProbe
    logger.info("[+] Module loaded: exploit.reflection_probe")
except Exception as e:
    logger.warning("[-] Failed to load exploit.reflection_probe", error=str(e))

try:
    from app.modules.exploit.sqli_fingerprint import SQLiFingerprint
    logger.info("[+] Module loaded: exploit.sqli_fingerprint")
except Exception as e:
    logger.warning("[-] Failed to load exploit.sqli_fingerprint", error=str(e))

try:
    from app.modules.exploit.secrets_scanner import SecretsScanner
    logger.info("[+] Module loaded: exploit.secrets_scanner")
except Exception as e:
    logger.warning("[-] Failed to load exploit.secrets_scanner", error=str(e))

# NOTE: darkweb.onion_crawler is loaded via app.darkweb.__init__ (imported by darkweb API router)
