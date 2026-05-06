"""
ShadowNet — Advanced DNS Reconnaissance
Performs zone-transfer probe (AXFR), DMARC / SPF / DKIM email-auth analysis,
DNSSEC validation, NS / MX / TXT / CAA enumeration, and DNS misconfiguration
checks. Free, no API key.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List, Optional

import dns.exception
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone

from app.modules.base import EntityFound, ModuleRegistry, OSINTModule, ScanResult


COMMON_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2", "mail",
    "smtp", "dkim", "everlytickey1", "everlytickey2", "mxvault", "s1", "s2",
    "amazon", "amazonses", "mandrill", "sendgrid", "fd", "sm", "scph0220",
    "20210112", "20161025",
]


class DNSAdvanced(OSINTModule):
    name = "recon.dns_advanced"
    description = "Deep DNS recon: zone transfer, DMARC/SPF/DKIM, DNSSEC, CAA, NS misconfig"
    supported_target_types = ["domain"]
    requires_api_key = False
    rate_limit = 30

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        domain = target.strip().lower().split("//")[-1].split("/")[0]
        data: Dict[str, Any] = {
            "domain": domain, "ns": [], "mx": [], "txt": [], "caa": [],
            "soa": None, "dnssec": None, "spf": None, "dmarc": None,
            "dkim_selectors": [], "zone_transfer": [], "issues": [],
        }
        entities: List[EntityFound] = []

        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5
        resolver.timeout = 5

        for rtype in ("NS", "MX", "TXT", "CAA", "SOA"):
            try:
                answers = await asyncio.to_thread(resolver.resolve, domain, rtype)
                for r in answers:
                    val = r.to_text().strip('"')
                    if rtype == "NS":
                        data["ns"].append(val.rstrip("."))
                    elif rtype == "MX":
                        data["mx"].append(val)
                    elif rtype == "TXT":
                        data["txt"].append(val)
                    elif rtype == "CAA":
                        data["caa"].append(val)
                    elif rtype == "SOA":
                        data["soa"] = val
            except Exception:
                pass

        for txt in data["txt"]:
            if txt.lower().startswith("v=spf1"):
                data["spf"] = txt
                if " +all" in txt or " all" in txt.split()[-1].lower() == "+all":
                    data["issues"].append({
                        "type": "spf_permissive",
                        "detail": "SPF policy ends with +all (permits any sender)",
                        "severity": "high",
                    })
                if "?all" in txt:
                    data["issues"].append({
                        "type": "spf_neutral",
                        "detail": "SPF policy ends with ?all (neutral, no enforcement)",
                        "severity": "medium",
                    })

        try:
            answers = await asyncio.to_thread(resolver.resolve, f"_dmarc.{domain}", "TXT")
            for r in answers:
                txt = r.to_text().strip('"')
                if txt.lower().startswith("v=dmarc1"):
                    data["dmarc"] = txt
                    if "p=none" in txt.lower():
                        data["issues"].append({
                            "type": "dmarc_monitor_only",
                            "detail": "DMARC policy is p=none (monitor only — no spoof prevention)",
                            "severity": "medium",
                        })
        except Exception:
            data["issues"].append({
                "type": "dmarc_missing",
                "detail": "No DMARC record found (domain is spoofable)",
                "severity": "high",
            })

        if not data["spf"]:
            data["issues"].append({
                "type": "spf_missing",
                "detail": "No SPF record found (any sender can pretend to be this domain)",
                "severity": "high",
            })

        if not data["caa"]:
            data["issues"].append({
                "type": "caa_missing",
                "detail": "No CAA record — any CA can issue certs for this domain",
                "severity": "low",
            })

        async def find_dkim(selector: str) -> Optional[str]:
            try:
                answers = await asyncio.to_thread(resolver.resolve, f"{selector}._domainkey.{domain}", "TXT")
                for r in answers:
                    txt = r.to_text().strip('"')
                    if "v=dkim1" in txt.lower() or "k=rsa" in txt.lower() or "p=" in txt.lower():
                        return txt
            except Exception:
                return None
            return None

        results = await asyncio.gather(*(find_dkim(s) for s in COMMON_DKIM_SELECTORS))
        for sel, val in zip(COMMON_DKIM_SELECTORS, results):
            if val:
                data["dkim_selectors"].append({"selector": sel, "value": val[:200]})

        for ns in data["ns"]:
            try:
                answer = await asyncio.to_thread(dns.query.xfr, ns, domain, lifetime=8.0)
                names_collected: List[str] = []
                for msg in answer:
                    for name, ttl, rdata in msg.answer[0].items.keys() if False else []:
                        pass
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=8))
                    for n in zone.nodes.keys():
                        names_collected.append(str(n) + "." + domain)
                except Exception:
                    pass
                if names_collected:
                    data["zone_transfer"].append({
                        "nameserver": ns, "records_count": len(names_collected),
                        "sample": names_collected[:25],
                    })
                    data["issues"].append({
                        "type": "zone_transfer_open",
                        "detail": f"AXFR allowed from {ns} — full zone disclosed ({len(names_collected)} records)",
                        "severity": "critical",
                    })
            except Exception:
                pass

        try:
            request = dns.message.make_query(domain, dns.rdatatype.DNSKEY, want_dnssec=True)
            response = await asyncio.to_thread(dns.query.udp, request, "1.1.1.1", timeout=5)
            data["dnssec"] = bool(response.answer and any(r.rdtype == dns.rdatatype.DNSKEY for r in response.answer))
            if not data["dnssec"]:
                data["issues"].append({
                    "type": "dnssec_disabled",
                    "detail": "DNSSEC is not enabled (DNS responses can be tampered)",
                    "severity": "low",
                })
        except Exception:
            data["dnssec"] = False

        for ns in data["ns"]:
            entities.append(EntityFound(
                entity_type="nameserver", value=ns, source=self.name, confidence=1.0,
                metadata={"domain": domain},
                relationships=[{"type": "AUTHORITATIVE_FOR", "target": domain}],
            ))
        for mx in data["mx"]:
            entities.append(EntityFound(
                entity_type="mail_server", value=mx, source=self.name, confidence=1.0,
                metadata={"domain": domain},
                relationships=[{"type": "RECEIVES_MAIL_FOR", "target": domain}],
            ))
        for issue in data["issues"]:
            entities.append(EntityFound(
                entity_type="email_misconfig" if "spf" in issue["type"] or "dmarc" in issue["type"] else "dns_misconfig",
                value=issue["type"], source=self.name,
                confidence=0.95,
                metadata={"detail": issue["detail"], "severity": issue["severity"], "domain": domain},
                relationships=[{"type": "AFFECTS", "target": domain}],
            ))

        critical = sum(1 for i in data["issues"] if i["severity"] == "critical")
        high = sum(1 for i in data["issues"] if i["severity"] == "high")
        severity = "critical" if critical else ("high" if high else ("medium" if data["issues"] else "info"))

        summary = (
            f"DNS-Advanced {domain}: {len(data['ns'])} NS | {len(data['mx'])} MX | "
            f"SPF={'yes' if data['spf'] else 'NO'} | DMARC={'yes' if data['dmarc'] else 'NO'} | "
            f"DNSSEC={'yes' if data['dnssec'] else 'no'} | "
            f"DKIM selectors found: {len(data['dkim_selectors'])} | "
            f"AXFR open: {len(data['zone_transfer'])} | "
            f"issues: {len(data['issues'])}"
        )

        return ScanResult(
            module=self.name, target=domain, success=True,
            entities=entities, raw_data=data, summary=summary, severity=severity,
        )


ModuleRegistry.register(DNSAdvanced())
