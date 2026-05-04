"""
ShadowNet — IP Geolocation Module
Free IP geolocation via ip-api.com (45 req/min, no key needed).
"""

import aiohttp
from typing import Dict, Any
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry


class IPGeolocation(OSINTModule):
    name = "network.ip_geolocation"
    description = "IP geolocation — country, city, ISP, ASN, coordinates (free, no key)"
    supported_target_types = ["ip"]
    requires_api_key = False
    rate_limit = 45  # ip-api.com free tier limit

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        ip = target.strip()
        entities = []

        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"

            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status != 200:
                        return ScanResult(
                            module=self.name, target=ip, success=False,
                            error=f"API returned {resp.status}",
                        )
                    data = await resp.json()

            if data.get("status") != "success":
                return ScanResult(
                    module=self.name, target=ip, success=False,
                    error=data.get("message", "Lookup failed"),
                )

            # Location entity
            entities.append(EntityFound(
                entity_type="location",
                value=f"{data.get('city', '')}, {data.get('regionName', '')}, {data.get('country', '')}",
                source=self.name, confidence=0.8,
                metadata={
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "country_code": data.get("countryCode"),
                    "zip": data.get("zip"),
                    "timezone": data.get("timezone"),
                },
                relationships=[{"type": "GEOLOCATED_AT", "target": ip}],
            ))

            # ISP/Org entity
            if data.get("isp"):
                entities.append(EntityFound(
                    entity_type="organization", value=data["isp"],
                    source=self.name, confidence=0.9,
                    metadata={"role": "ISP", "asn": data.get("as"), "asname": data.get("asname")},
                    relationships=[{"type": "HOSTED_BY", "target": ip}],
                ))

            # Reverse DNS
            if data.get("reverse"):
                entities.append(EntityFound(
                    entity_type="domain", value=data["reverse"],
                    source=self.name, confidence=0.9,
                    metadata={"source": "reverse_dns"},
                    relationships=[{"type": "REVERSE_DNS", "target": ip}],
                ))

            # Flags
            flags = []
            if data.get("proxy"):
                flags.append("🔒 Proxy/VPN detected")
            if data.get("hosting"):
                flags.append("☁️ Hosting/Data center IP")
            if data.get("mobile"):
                flags.append("📱 Mobile network")

            summary = (
                f"IP: {ip} | Location: {data.get('city')}, {data.get('country')} "
                f"| ISP: {data.get('isp')} | ASN: {data.get('as')} "
                f"| Coords: {data.get('lat')},{data.get('lon')}"
            )
            if flags:
                summary += " | " + " | ".join(flags)

            return ScanResult(
                module=self.name, target=ip, success=True,
                entities=entities, raw_data=data, summary=summary,
                severity="medium" if data.get("proxy") else "info",
            )

        except Exception as e:
            return ScanResult(
                module=self.name, target=ip, success=False, error=str(e),
            )


ModuleRegistry.register(IPGeolocation())
