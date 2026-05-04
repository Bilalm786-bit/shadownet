# ShadowNet — OSINT Modules Package
# Import all modules to trigger auto-registration with ModuleRegistry
# Each import is wrapped in try/except so missing deps don't break the app

import structlog
logger = structlog.get_logger(__name__)

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
    # BUG FIX: Class name is DocumentOSINT, NOT MetadataExtractor
    from app.modules.document.metadata_extractor import DocumentOSINT
    logger.info("[+] Module loaded: document.metadata_extractor")
except Exception as e:
    logger.warning("[-] Failed to load document.metadata_extractor", error=str(e))

try:
    from app.modules.socmint.github_recon import GitHubRecon
    logger.info("[+] Module loaded: socmint.github_recon")
except Exception as e:
    logger.warning("[-] Failed to load socmint.github_recon", error=str(e))

try:
    from app.modules.breach.google_dorker import GoogleDorker
    logger.info("[+] Module loaded: breach.google_dorker")
except Exception as e:
    logger.warning("[-] Failed to load breach.google_dorker", error=str(e))

# NOTE: darkweb.onion_crawler is loaded via app.darkweb.__init__ (imported by darkweb API router)
# Do NOT import it here — causes circular import with app.darkweb package.
