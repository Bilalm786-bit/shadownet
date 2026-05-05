"""
ShadowNet — SSL/TLS Certificate Analyzer
Direct TLS connection for certificate analysis — SANs, chain, cipher, expiry.
"""

import ssl
import socket
import asyncio
from datetime import datetime, timezone
from typing import Dict, Any
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry
import structlog

logger = structlog.get_logger(__name__)


class SSLAnalyzer(OSINTModule):
    name = "network.ssl_analyzer"
    description = "SSL/TLS certificate analysis — SANs, chain, cipher, expiry, issuer (free, no key)"
    supported_target_types = ["domain"]
    requires_api_key = False

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        domain = target.strip().lower()
        entities = []

        try:
            cert_data = await asyncio.get_event_loop().run_in_executor(
                None, self._get_cert_info, domain
            )
        except Exception as e:
            return ScanResult(module=self.name, target=domain, success=False, error=str(e))

        if not cert_data:
            return ScanResult(module=self.name, target=domain, success=False, error="Could not retrieve SSL certificate")

        # Extract SANs — discover hidden domains
        sans = cert_data.get("sans", [])
        for san in sans:
            if san != domain and "*" not in san:
                entities.append(EntityFound(
                    entity_type="domain", value=san, source=self.name, confidence=1.0,
                    metadata={"source": "SSL_SAN", "cert_issuer": cert_data.get("issuer")},
                    relationships=[{"type": "SHARES_CERT_WITH", "target": domain}],
                ))

        # Issuer entity
        if cert_data.get("issuer"):
            entities.append(EntityFound(
                entity_type="organization", value=cert_data["issuer"], source=self.name,
                confidence=0.9, metadata={"role": "certificate_authority"},
                relationships=[{"type": "ISSUED_BY", "target": domain}],
            ))

        # Check for issues
        issues = []
        days_left = cert_data.get("days_until_expiry", 999)
        if days_left < 0:
            issues.append("❌ CERTIFICATE EXPIRED")
        elif days_left < 30:
            issues.append(f"⚠️ Expires in {days_left} days")

        if cert_data.get("self_signed"):
            issues.append("⚠️ Self-signed certificate")

        severity = "critical" if days_left < 0 else ("high" if issues else "info")

        summary = (
            f"SSL: {domain} | Issuer: {cert_data.get('issuer', 'N/A')} | "
            f"Expires: {cert_data.get('not_after', 'N/A')} ({days_left}d) | "
            f"SANs: {len(sans)} domains | Protocol: {cert_data.get('protocol', 'N/A')}"
        )
        if issues:
            summary += " | " + " | ".join(issues)

        return ScanResult(
            module=self.name, target=domain, success=True,
            entities=entities, raw_data=cert_data, summary=summary, severity=severity,
        )

    def _get_cert_info(self, domain: str) -> Dict[str, Any]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if not cert:
                    # Try binary form
                    import ssl as _ssl
                    ctx2 = ssl.create_default_context()
                    with socket.create_connection((domain, 443), timeout=10) as s2:
                        with ctx2.wrap_socket(s2, server_hostname=domain) as ss2:
                            cert = ss2.getpeercert()

                protocol = ssock.version()
                cipher = ssock.cipher()

        if not cert:
            return {}

        # Parse subject
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))

        # Parse SANs
        sans = []
        for type_name, value in cert.get("subjectAltName", []):
            if type_name == "DNS":
                sans.append(value.lower())

        # Parse dates
        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")
        days_until_expiry = 999
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_until_expiry = (expiry - datetime.now(timezone.utc)).days
        except Exception:
            pass

        issuer_org = issuer.get("organizationName", issuer.get("commonName", "Unknown"))
        self_signed = subject.get("commonName") == issuer.get("commonName") and not issuer.get("organizationName")

        return {
            "subject": subject.get("commonName", ""),
            "issuer": issuer_org,
            "issuer_cn": issuer.get("commonName", ""),
            "not_before": not_before,
            "not_after": not_after,
            "days_until_expiry": days_until_expiry,
            "serial_number": cert.get("serialNumber", ""),
            "sans": sans,
            "san_count": len(sans),
            "protocol": protocol,
            "cipher": cipher[0] if cipher else "",
            "cipher_bits": cipher[2] if cipher and len(cipher) > 2 else 0,
            "self_signed": self_signed,
            "subject_org": subject.get("organizationName", ""),
        }


ModuleRegistry.register(SSLAnalyzer())
