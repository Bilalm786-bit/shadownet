"""
ShadowNet — Subdomain Enumeration Module
Uses crt.sh Certificate Transparency logs — completely free, no API key.
"""

import aiohttp
from typing import Dict, Any, Set
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry


class SubdomainEnum(OSINTModule):
    name = "network.subdomain_enum"
    description = "Subdomain discovery via Certificate Transparency logs (crt.sh, free)"
    supported_target_types = ["domain"]
    requires_api_key = False

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        domain = target.strip().lower()
        entities = []
        subdomains: Set[str] = set()

        # 1. crt.sh Certificate Transparency
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        certs = await resp.json()
                        for cert in certs:
                            name_value = cert.get("name_value", "")
                            for name in name_value.split("\n"):
                                name = name.strip().lower()
                                if name and name.endswith(domain) and "*" not in name:
                                    subdomains.add(name)
        except Exception:
            pass

        # 2. Additional free sources — DNS common subdomains bruteforce
        common_subs = [
            "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
            "admin", "portal", "vpn", "remote", "api", "dev", "staging",
            "test", "beta", "demo", "app", "mobile", "m", "cdn", "static",
            "assets", "media", "img", "images", "ns1", "ns2", "dns",
            "mx", "relay", "gateway", "proxy", "git", "gitlab", "jenkins",
            "ci", "jira", "confluence", "wiki", "docs", "blog", "forum",
            "shop", "store", "pay", "checkout", "secure", "login", "sso",
            "auth", "oauth", "id", "accounts", "dashboard", "panel",
            "cp", "cpanel", "whm", "plesk", "db", "database", "mysql",
            "postgres", "mongo", "redis", "elastic", "kibana", "grafana",
            "prometheus", "monitoring", "status", "health", "backup",
            "s3", "storage", "files", "download", "upload", "cloud",
            "aws", "azure", "gcp", "k8s", "docker", "registry",
            "internal", "intranet", "extranet", "private", "corp",
            "office", "exchange", "autodiscover", "lyncdiscover",
        ]

        import dns.resolver
        for sub in common_subs:
            fqdn = f"{sub}.{domain}"
            try:
                dns.resolver.resolve(fqdn, "A")
                subdomains.add(fqdn)
            except Exception:
                pass

        # Build entities
        for subdomain in sorted(subdomains):
            entities.append(EntityFound(
                entity_type="domain", value=subdomain, source=self.name,
                confidence=1.0,
                metadata={"parent_domain": domain, "source": "cert_transparency"},
                relationships=[{"type": "SUBDOMAIN_OF", "target": domain}],
            ))

        return ScanResult(
            module=self.name, target=domain, success=True,
            entities=entities,
            raw_data={"subdomains": sorted(subdomains), "total": len(subdomains)},
            summary=f"Found {len(subdomains)} subdomains for {domain}",
            severity="medium" if len(subdomains) > 20 else "info",
        )


ModuleRegistry.register(SubdomainEnum())
