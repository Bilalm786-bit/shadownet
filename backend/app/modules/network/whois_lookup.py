"""
ShadowNet — WHOIS Lookup Module
Domain/IP registration data lookup.
NO API key — uses python-whois library.
"""

import asyncio
import whois
from typing import Dict, Any
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry


class WhoisLookup(OSINTModule):
    name = "network.whois_lookup"
    description = "WHOIS registration data — registrar, dates, nameservers, contact info"
    supported_target_types = ["domain", "ip"]
    requires_api_key = False

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        target = target.strip().lower()
        entities = []

        try:
            # python-whois is blocking → execute in a thread with a timeout
            w = await asyncio.wait_for(
                asyncio.to_thread(whois.whois, target),
                timeout=20,
            )
            data = {}

            # Extract all available fields
            field_map = {
                "domain_name": w.domain_name,
                "registrar": w.registrar,
                "whois_server": w.whois_server,
                "creation_date": str(w.creation_date) if w.creation_date else None,
                "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                "updated_date": str(w.updated_date) if w.updated_date else None,
                "name_servers": w.name_servers if isinstance(w.name_servers, list) else [w.name_servers] if w.name_servers else [],
                "status": w.status if isinstance(w.status, list) else [w.status] if w.status else [],
                "emails": w.emails if isinstance(w.emails, list) else [w.emails] if w.emails else [],
                "dnssec": w.dnssec,
                "org": w.org,
                "city": w.city,
                "state": w.state,
                "country": w.country,
                "registrant": getattr(w, "registrant", None),
                "admin_email": getattr(w, "admin_email", None),
                "tech_email": getattr(w, "tech_email", None),
            }

            data = {k: v for k, v in field_map.items() if v}

            # Create entities from discovered data
            if data.get("registrar"):
                entities.append(EntityFound(
                    entity_type="organization", value=str(data["registrar"]),
                    source=self.name, confidence=0.9,
                    metadata={"role": "registrar"},
                    relationships=[{"type": "REGISTERED_BY", "target": target}],
                ))

            if data.get("org"):
                entities.append(EntityFound(
                    entity_type="organization", value=str(data["org"]),
                    source=self.name, confidence=0.8,
                    metadata={"role": "registrant_org"},
                    relationships=[{"type": "OWNED_BY", "target": target}],
                ))

            for email in data.get("emails", []):
                if email:
                    entities.append(EntityFound(
                        entity_type="email", value=str(email),
                        source=self.name, confidence=0.9,
                        metadata={"source": "whois"},
                        relationships=[{"type": "CONTACT_FOR", "target": target}],
                    ))

            for ns in data.get("name_servers", []):
                if ns:
                    entities.append(EntityFound(
                        entity_type="domain", value=str(ns).lower(),
                        source=self.name, confidence=1.0,
                        metadata={"role": "nameserver"},
                        relationships=[{"type": "NAMESERVER_FOR", "target": target}],
                    ))

            if data.get("country"):
                entities.append(EntityFound(
                    entity_type="location", value=str(data["country"]),
                    source=self.name, confidence=0.7,
                    metadata={"city": data.get("city"), "state": data.get("state")},
                    relationships=[{"type": "REGISTERED_IN", "target": target}],
                ))

            summary = f"WHOIS for {target}: Registrar={data.get('registrar', 'N/A')} | Org={data.get('org', 'N/A')} | Created={data.get('creation_date', 'N/A')} | Country={data.get('country', 'N/A')}"

            return ScanResult(
                module=self.name, target=target, success=True,
                entities=entities, raw_data=data, summary=summary,
            )

        except Exception as e:
            return ScanResult(
                module=self.name, target=target, success=False,
                error=str(e), summary=f"WHOIS lookup failed for {target}",
            )


ModuleRegistry.register(WhoisLookup())
