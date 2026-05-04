"""
ShadowNet — Email Validator Module
MX record verification, syntax check, and Gravatar lookup.
NO API key required.
"""

import dns.resolver
import hashlib
import aiohttp
import re
from typing import Dict, Any
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry


class EmailValidator(OSINTModule):
    name = "identity.email_validator"
    description = "Validates email format, checks MX records, and looks up Gravatar"
    supported_target_types = ["email"]
    requires_api_key = False

    EMAIL_REGEX = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        email = target.strip().lower()
        entities = []
        findings = {
            "email": email,
            "valid_format": False,
            "mx_records": [],
            "domain": "",
            "gravatar_url": None,
            "disposable": False,
        }

        # 1. Syntax validation
        if not self.EMAIL_REGEX.match(email):
            return ScanResult(
                module=self.name, target=email, success=True,
                summary=f"Invalid email format: {email}",
                raw_data=findings, severity="info",
            )
        findings["valid_format"] = True

        # 2. Extract domain
        domain = email.split("@")[1]
        findings["domain"] = domain

        # 3. MX record lookup
        try:
            mx_records = dns.resolver.resolve(domain, "MX")
            findings["mx_records"] = [
                {"priority": r.preference, "host": str(r.exchange).rstrip(".")}
                for r in mx_records
            ]
            entities.append(EntityFound(
                entity_type="domain",
                value=domain,
                source=self.name,
                confidence=1.0,
                metadata={"mx_records": findings["mx_records"]},
                relationships=[{"type": "BELONGS_TO_DOMAIN", "target": email}],
            ))
        except Exception:
            findings["mx_records"] = []

        # 4. Gravatar lookup
        email_hash = hashlib.md5(email.encode()).hexdigest()
        gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(gravatar_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        findings["gravatar_url"] = f"https://www.gravatar.com/avatar/{email_hash}"
                        entities.append(EntityFound(
                            entity_type="profile_image",
                            value=findings["gravatar_url"],
                            source=self.name,
                            confidence=0.9,
                            metadata={"platform": "Gravatar"},
                            relationships=[{"type": "HAS_AVATAR", "target": email}],
                        ))
        except Exception:
            pass

        # 5. Check for known disposable email providers
        disposable_domains = {
            "tempmail.com", "guerrillamail.com", "mailinator.com", "throwaway.email",
            "yopmail.com", "10minutemail.com", "trashmail.com", "sharklasers.com",
            "maildrop.cc", "temp-mail.org", "dispostable.com", "fakeinbox.com",
        }
        if domain in disposable_domains:
            findings["disposable"] = True

        has_mx = len(findings["mx_records"]) > 0
        summary_parts = [
            f"Email: {email}",
            f"Valid format: ✓" if findings["valid_format"] else "Invalid format",
            f"MX records: {len(findings['mx_records'])} found" if has_mx else "No MX records",
            f"Gravatar: Found" if findings["gravatar_url"] else "Gravatar: Not found",
            f"⚠️ Disposable email!" if findings["disposable"] else "",
        ]

        return ScanResult(
            module=self.name,
            target=email,
            success=True,
            entities=entities,
            raw_data=findings,
            summary=" | ".join(filter(None, summary_parts)),
            severity="medium" if findings["disposable"] else "info",
        )


ModuleRegistry.register(EmailValidator())
