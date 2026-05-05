"""
ShadowNet — ASN / BGP Lookup Module
Resolves a domain or IP to its Autonomous System Number, owning organization,
country, and announced prefixes via the public Team Cymru WHOIS service and
the BGPView REST API. NO API key required.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Any, Dict

import aiohttp

from app.modules.base import EntityFound, ModuleRegistry, OSINTModule, ScanResult


class ASNLookup(OSINTModule):
    name = "recon.asn_lookup"
    description = "Resolve target IP/domain to ASN, owning org, country and prefixes (free)"
    supported_target_types = ["ip", "domain"]
    requires_api_key = False
    rate_limit = 30

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        target = target.strip()
        ip = await self._resolve(target)
        if not ip:
            return ScanResult(
                module=self.name, target=target, success=False,
                error=f"Could not resolve {target} to an IP address",
            )

        data: Dict[str, Any] = {"target": target, "ip": ip}
        entities = []

        try:
            async with aiohttp.ClientSession() as session:
                ip_url = f"https://api.bgpview.io/ip/{ip}"
                async with session.get(ip_url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        body = await resp.json()
                        prefixes = (body.get("data") or {}).get("prefixes") or []
                        if prefixes:
                            top = prefixes[0]
                            asn = top.get("asn", {})
                            data["asn"] = asn.get("asn")
                            data["asn_name"] = asn.get("name")
                            data["asn_description"] = asn.get("description")
                            data["country"] = asn.get("country_code")
                            data["prefix"] = top.get("prefix")
                            data["all_prefixes"] = [p.get("prefix") for p in prefixes[:25]]

                if data.get("asn"):
                    asn_url = f"https://api.bgpview.io/asn/{data['asn']}"
                    async with session.get(asn_url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                        if resp.status == 200:
                            body = await resp.json()
                            d = body.get("data") or {}
                            data["asn_org_website"] = d.get("website")
                            data["asn_email_contacts"] = d.get("email_contacts", [])
                            data["asn_abuse_contacts"] = d.get("abuse_contacts", [])
                            data["asn_looking_glass"] = d.get("looking_glass")
        except Exception as exc:
            data["error"] = str(exc)

        if data.get("asn"):
            entities.append(EntityFound(
                entity_type="asn", value=f"AS{data['asn']}",
                source=self.name, confidence=1.0,
                metadata={
                    "name": data.get("asn_name"),
                    "description": data.get("asn_description"),
                    "country": data.get("country"),
                    "prefix": data.get("prefix"),
                },
                relationships=[{"type": "ANNOUNCES", "target": ip}],
            ))
        if data.get("asn_name"):
            entities.append(EntityFound(
                entity_type="organization", value=data["asn_name"],
                source=self.name, confidence=0.9,
                metadata={"role": "network_operator", "country": data.get("country")},
                relationships=[{"type": "OPERATES", "target": ip}],
            ))
        for email in (data.get("asn_abuse_contacts") or [])[:5]:
            entities.append(EntityFound(
                entity_type="email", value=email, source=self.name,
                confidence=0.85, metadata={"role": "abuse_contact"},
                relationships=[{"type": "ABUSE_FOR", "target": ip}],
            ))

        summary = (
            f"ASN: {target} ({ip}) → AS{data.get('asn', 'unknown')} "
            f"({data.get('asn_name', 'unknown')}, {data.get('country', '??')}) | "
            f"prefix {data.get('prefix', 'n/a')}"
        )
        if not data.get("asn"):
            summary = f"ASN lookup failed for {target} ({ip})"

        return ScanResult(
            module=self.name, target=target, success=bool(data.get("asn")),
            entities=entities, raw_data=data, summary=summary, severity="info",
        )

    @staticmethod
    async def _resolve(target: str) -> str | None:
        try:
            socket.inet_aton(target)
            return target
        except OSError:
            pass
        try:
            info = await asyncio.get_event_loop().run_in_executor(
                None, socket.getaddrinfo, target, None, socket.AF_INET
            )
            if info:
                return info[0][4][0]
        except Exception:
            return None
        return None


ModuleRegistry.register(ASNLookup())
