"""
ShadowNet — Threat Intelligence Subsystem
Aggregates real-time IOCs (Indicators of Compromise) from open threat-intel feeds:
  - URLhaus (abuse.ch) — malicious URLs
  - ThreatFox (abuse.ch) — IOC database (IP, domain, hash, URL)
  - Feodo Tracker (abuse.ch) — botnet C2 IPs
  - OpenPhish — live phishing URLs
  - PhishTank — phishing URLs (free tier, no key)
  - CISA KEV — Known Exploited Vulnerabilities
  - NVD — recent CVEs
  - AlienVault OTX (public pulses)
  - Tor Exit Node list
  - Spamhaus DROP / EDROP
All sources are free / public. No API keys required.
"""
from app.threat_intel.feeds import threat_intel_aggregator  # noqa: F401
from app.threat_intel.scheduler import threat_intel_scheduler  # noqa: F401
