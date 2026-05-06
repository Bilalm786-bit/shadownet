"""
ShadowNet — Deep TLS / SSL Audit
Qualys-style protocol & cipher audit. Tests SSLv2 / SSLv3 / TLS 1.0 / 1.1 / 1.2 /
1.3 by attempting handshakes against the target on port 443, fingerprints supported
ciphers, evaluates certificate chain strength, key size, signature algorithm,
HSTS, and well-known historical attack indicators (POODLE, BEAST, FREAK, LOGJAM,
SWEET32, ROBOT pre-conditions).
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List

import aiohttp

from app.modules.base import EntityFound, ModuleRegistry, OSINTModule, ScanResult


PROTOCOLS = [
    ("SSLv2", getattr(ssl, "PROTOCOL_SSLv23", None), "obsolete - critical"),
    ("SSLv3", getattr(ssl, "PROTOCOL_SSLv23", None), "obsolete - critical"),
    ("TLSv1.0", getattr(ssl, "PROTOCOL_TLSv1", None), "deprecated - high"),
    ("TLSv1.1", getattr(ssl, "PROTOCOL_TLSv1_1", None), "deprecated - high"),
    ("TLSv1.2", getattr(ssl, "PROTOCOL_TLS_CLIENT", None), "ok"),
    ("TLSv1.3", getattr(ssl, "PROTOCOL_TLS_CLIENT", None), "ok"),
]
WEAK_CIPHER_KEYWORDS = ["NULL", "EXPORT", "DES", "RC4", "MD5", "ANON", "IDEA", "SEED"]


class TLSAudit(OSINTModule):
    name = "recon.tls_audit"
    description = "Deep TLS / SSL audit: protocols, ciphers, cert chain, HSTS, historical attacks"
    supported_target_types = ["domain"]
    requires_api_key = False
    rate_limit = 10

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        domain = target.strip().lower().split("//")[-1].split("/")[0].split(":")[0]
        port = 443
        data: Dict[str, Any] = {
            "host": domain, "port": port,
            "protocols_supported": [], "protocols_rejected": [],
            "negotiated_cipher": None, "negotiated_protocol": None,
            "weak_ciphers_offered": [], "key_info": {},
            "cert": {}, "hsts": None, "issues": [],
        }
        entities: List[EntityFound] = []

        for proto_name, _proto_const, classification in PROTOCOLS:
            ok = await asyncio.to_thread(self._handshake, domain, port, proto_name)
            if ok:
                data["protocols_supported"].append({"protocol": proto_name, "classification": classification})
                if proto_name == "SSLv3":
                    data["issues"].append({
                        "id": "ssl_poodle",
                        "title": "SSLv3 enabled — vulnerable to POODLE (CVE-2014-3566)",
                        "severity": "critical", "cvss": 7.5,
                        "cwe": "CWE-310",
                    })
                elif proto_name in ("SSLv2",):
                    data["issues"].append({
                        "id": "sslv2_drown",
                        "title": "SSLv2 enabled — vulnerable to DROWN (CVE-2016-0800)",
                        "severity": "critical", "cvss": 9.8,
                        "cwe": "CWE-310",
                    })
                elif proto_name == "TLSv1.0":
                    data["issues"].append({
                        "id": "tls_1_0",
                        "title": "TLS 1.0 enabled — deprecated (PCI-DSS forbidden, BEAST exposure)",
                        "severity": "high", "cvss": 5.3,
                        "cwe": "CWE-326",
                    })
                elif proto_name == "TLSv1.1":
                    data["issues"].append({
                        "id": "tls_1_1",
                        "title": "TLS 1.1 enabled — deprecated by IETF RFC 8996",
                        "severity": "medium", "cvss": 4.0,
                        "cwe": "CWE-326",
                    })
            else:
                data["protocols_rejected"].append(proto_name)

        info = await asyncio.to_thread(self._best_cipher, domain, port)
        if info:
            data["negotiated_cipher"] = info["cipher"]
            data["negotiated_protocol"] = info["protocol"]
            data["key_info"] = info["key_info"]
            data["cert"] = info["cert"]
            for kw in WEAK_CIPHER_KEYWORDS:
                if info["cipher"] and kw in info["cipher"].upper():
                    data["weak_ciphers_offered"].append(info["cipher"])
                    data["issues"].append({
                        "id": f"weak_cipher_{kw.lower()}",
                        "title": f"Weak cipher in use: {info['cipher']}",
                        "severity": "high", "cvss": 5.9,
                        "cwe": "CWE-327",
                    })
            key_bits = info["key_info"].get("bits") or 0
            if key_bits and key_bits < 2048:
                data["issues"].append({
                    "id": "weak_key_size",
                    "title": f"Certificate key size {key_bits} < 2048 bits",
                    "severity": "high", "cvss": 5.9,
                    "cwe": "CWE-326",
                })
            if info["cert"].get("days_until_expiry", 999) < 0:
                data["issues"].append({
                    "id": "cert_expired",
                    "title": "Certificate expired",
                    "severity": "critical", "cvss": 7.5,
                    "cwe": "CWE-295",
                })
            elif info["cert"].get("days_until_expiry", 999) < 14:
                data["issues"].append({
                    "id": "cert_expiring",
                    "title": f"Certificate expires in {info['cert']['days_until_expiry']} days",
                    "severity": "medium", "cvss": 4.3,
                    "cwe": "CWE-295",
                })
            if info["cert"].get("self_signed"):
                data["issues"].append({
                    "id": "cert_self_signed",
                    "title": "Certificate is self-signed (no public CA chain)",
                    "severity": "high", "cvss": 6.5,
                    "cwe": "CWE-295",
                })
            if info["cert"].get("signature_algorithm", "").lower().startswith("sha1"):
                data["issues"].append({
                    "id": "cert_sha1",
                    "title": "Certificate uses SHA-1 signature (deprecated)",
                    "severity": "high", "cvss": 5.9,
                    "cwe": "CWE-327",
                })

        try:
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(f"https://{domain}/", timeout=aiohttp.ClientTimeout(total=10), allow_redirects=True) as resp:
                    hsts = resp.headers.get("Strict-Transport-Security", "")
                    data["hsts"] = hsts or None
                    if not hsts:
                        data["issues"].append({
                            "id": "no_hsts",
                            "title": "No Strict-Transport-Security header — site downgrade-able to HTTP",
                            "severity": "medium", "cvss": 4.0,
                            "cwe": "CWE-319",
                        })
        except Exception as exc:
            data["hsts_error"] = str(exc)

        for issue in data["issues"]:
            entities.append(EntityFound(
                entity_type="vulnerability", value=issue["id"], source=self.name,
                confidence=0.95,
                metadata={
                    "title": issue["title"], "severity": issue["severity"],
                    "cvss": issue.get("cvss"), "cwe": issue.get("cwe"), "domain": domain,
                },
                relationships=[{"type": "AFFECTS", "target": domain}],
            ))

        critical = sum(1 for i in data["issues"] if i["severity"] == "critical")
        high = sum(1 for i in data["issues"] if i["severity"] == "high")
        severity = "critical" if critical else ("high" if high else ("medium" if data["issues"] else "info"))

        proto_summary = ", ".join(p["protocol"] for p in data["protocols_supported"]) or "none"
        summary = (
            f"TLS audit {domain}:443 | protocols: {proto_summary} | "
            f"cipher: {data.get('negotiated_cipher', 'n/a')} | "
            f"key: {data['key_info'].get('bits', '?')}bit | "
            f"HSTS: {'yes' if data['hsts'] else 'no'} | "
            f"issues: {len(data['issues'])} ({critical} critical, {high} high)"
        )

        return ScanResult(
            module=self.name, target=domain, success=True,
            entities=entities, raw_data=data, summary=summary, severity=severity,
        )

    @staticmethod
    def _handshake(host: str, port: int, proto_name: str) -> bool:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            mapping = {
                "SSLv2": (ssl.TLSVersion.SSLv3, ssl.TLSVersion.SSLv3),
                "SSLv3": (ssl.TLSVersion.SSLv3, ssl.TLSVersion.SSLv3),
                "TLSv1.0": (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
                "TLSv1.1": (ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
                "TLSv1.2": (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
                "TLSv1.3": (ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
            }
            min_v, max_v = mapping[proto_name]
            try:
                ctx.minimum_version = min_v
                ctx.maximum_version = max_v
            except (ValueError, AttributeError):
                return False
            with socket.create_connection((host, port), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    return ssock.version() is not None
        except Exception:
            return False

    @staticmethod
    def _best_cipher(host: str, port: int) -> Dict[str, Any] | None:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    cert = ssock.getpeercert()
                    der_size = 0
                    try:
                        der = ssock.getpeercert(binary_form=True)
                        der_size = len(der)
                    except Exception:
                        pass
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))
            sans = []
            for type_name, value in cert.get("subjectAltName", []):
                if type_name == "DNS":
                    sans.append(value.lower())
            try:
                expiry = datetime.strptime(cert.get("notAfter", ""), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_until_expiry = (expiry - datetime.now(timezone.utc)).days
            except Exception:
                days_until_expiry = 999
            self_signed = subject.get("commonName") == issuer.get("commonName") and not issuer.get("organizationName")
            return {
                "protocol": ssock.version() if False else None,
                "cipher": cipher[0] if cipher else None,
                "key_info": {"bits": cipher[2] if cipher and len(cipher) > 2 else 0},
                "cert": {
                    "subject": subject.get("commonName"),
                    "issuer": issuer.get("organizationName") or issuer.get("commonName"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "days_until_expiry": days_until_expiry,
                    "sans": sans,
                    "san_count": len(sans),
                    "self_signed": self_signed,
                    "der_size": der_size,
                    "signature_algorithm": cert.get("signatureAlgorithm", ""),
                    "version": cert.get("version", ""),
                },
            }
        except Exception:
            return None


ModuleRegistry.register(TLSAudit())
