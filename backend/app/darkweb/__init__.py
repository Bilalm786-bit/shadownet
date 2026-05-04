"""
ShadowNet — Dark Web Intelligence Engine
Provides dark web monitoring, onion crawling, threat classification, and Tor routing.
"""

import structlog

logger = structlog.get_logger(__name__)

# Import dark web components with proper error logging
try:
    from app.darkweb.onion_crawler import OnionCrawler
    logger.info("[+] Dark web component loaded: OnionCrawler")
except Exception as e:
    logger.warning("[-] Failed to load OnionCrawler", error=str(e), exc_info=True)
    OnionCrawler = None

try:
    from app.darkweb.tor_router import tor_router, TorRouter
    logger.info("[+] Dark web component loaded: TorRouter")
except Exception as e:
    logger.warning("[-] Failed to load TorRouter", error=str(e), exc_info=True)
    tor_router = None
    TorRouter = None

try:
    from app.darkweb.threat_classifier import ThreatClassifier, threat_classifier
    logger.info("[+] Dark web component loaded: ThreatClassifier")
except Exception as e:
    logger.warning("[-] Failed to load ThreatClassifier", error=str(e), exc_info=True)
    ThreatClassifier = None
    threat_classifier = None

__all__ = ["OnionCrawler", "TorRouter", "tor_router", "ThreatClassifier", "threat_classifier"]
