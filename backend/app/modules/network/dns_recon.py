"""
ShadowNet — DNS Reconnaissance Module
Full DNS enumeration: A, AAAA, MX, NS, TXT, SOA, CNAME records.
NO API key — uses dnspython library.
"""

import asyncio
import dns.resolver
import dns.reversename
from typing import Dict, Any, List
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry


class DNSRecon(OSINTModule):
    name = "network.dns_recon"
    description = "Full DNS enumeration — A, AAAA, MX, NS, TXT, SOA, CNAME, PTR records"
    supported_target_types = ["domain"]
    requires_api_key = False

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA"]

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        domain = target.strip().lower()
        entities = []
        dns_records = {}

        # dns.resolver is blocking → run in thread pool with a tight timeout
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        for rtype in self.RECORD_TYPES:
            try:
                answers = await asyncio.to_thread(resolver.resolve, domain, rtype)
                records = []
                for rdata in answers:
                    record_str = str(rdata).rstrip(".")
                    records.append(record_str)

                    # Create entities for discovered records
                    if rtype == "A":
                        entities.append(EntityFound(
                            entity_type="ip", value=record_str, source=self.name,
                            confidence=1.0,
                            metadata={"record_type": "A", "domain": domain},
                            relationships=[{"type": "RESOLVES_TO", "target": domain}],
                        ))
                    elif rtype == "MX":
                        mx_host = record_str.split()[-1] if " " in record_str else record_str
                        entities.append(EntityFound(
                            entity_type="domain", value=mx_host, source=self.name,
                            confidence=1.0,
                            metadata={"record_type": "MX", "priority": record_str.split()[0] if " " in record_str else "10"},
                            relationships=[{"type": "MAIL_SERVER_FOR", "target": domain}],
                        ))
                    elif rtype == "NS":
                        entities.append(EntityFound(
                            entity_type="domain", value=record_str, source=self.name,
                            confidence=1.0,
                            metadata={"record_type": "NS"},
                            relationships=[{"type": "NAMESERVER_FOR", "target": domain}],
                        ))
                    elif rtype == "TXT":
                        # Detect SPF, DKIM, DMARC
                        if "v=spf" in record_str.lower():
                            entities.append(EntityFound(
                                entity_type="security_config", value=f"SPF:{domain}",
                                source=self.name, confidence=1.0,
                                metadata={"type": "SPF", "record": record_str},
                            ))
                        elif "v=dmarc" in record_str.lower():
                            entities.append(EntityFound(
                                entity_type="security_config", value=f"DMARC:{domain}",
                                source=self.name, confidence=1.0,
                                metadata={"type": "DMARC", "record": record_str},
                            ))

                dns_records[rtype] = records
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                dns_records[rtype] = []
            except Exception:
                dns_records[rtype] = []

        # Zone transfer attempt
        zone_transfer = []
        ns_records = dns_records.get("NS", [])
        for ns in ns_records:
            try:
                import dns.zone
                import dns.query
                z = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
                for name, node in z.nodes.items():
                    zone_transfer.append(str(name))
            except Exception:
                pass

        if zone_transfer:
            dns_records["ZONE_TRANSFER"] = zone_transfer
            entities.append(EntityFound(
                entity_type="vulnerability", value=f"Zone Transfer Enabled: {domain}",
                source=self.name, confidence=1.0,
                metadata={"records_exposed": len(zone_transfer)},
            ))

        total_records = sum(len(v) for v in dns_records.values())
        summary = f"DNS recon for {domain}: {total_records} records found across {len([k for k, v in dns_records.items() if v])} record types"
        if zone_transfer:
            summary += f" | ⚠️ ZONE TRANSFER ENABLED ({len(zone_transfer)} records)"

        return ScanResult(
            module=self.name, target=domain, success=True,
            entities=entities, raw_data=dns_records, summary=summary,
            severity="critical" if zone_transfer else "info",
        )


ModuleRegistry.register(DNSRecon())
