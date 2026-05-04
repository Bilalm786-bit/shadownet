"""
ShadowNet — Phone Number Lookup Module
Carrier detection, geo-location, and format validation.
NO API key — uses the phonenumbers library (Google's libphonenumber).
"""

import phonenumbers
from phonenumbers import carrier, geocoder, timezone
from typing import Dict, Any
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry


class PhoneLookup(OSINTModule):
    name = "identity.phone_lookup"
    description = "Phone number validation, carrier detection, and geolocation (free, offline)"
    supported_target_types = ["phone"]
    requires_api_key = False

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        phone = target.strip()
        findings = {
            "input": phone,
            "valid": False,
            "possible": False,
            "phone_type": "",
            "carrier": "",
            "country": "",
            "region": "",
            "timezones": [],
            "international_format": "",
            "national_format": "",
            "e164_format": "",
            "country_code": None,
        }

        try:
            # Parse number (try with + prefix if not present)
            if not phone.startswith("+"):
                phone = "+" + phone
            parsed = phonenumbers.parse(phone, None)

            findings["valid"] = phonenumbers.is_valid_number(parsed)
            findings["possible"] = phonenumbers.is_possible_number(parsed)
            findings["country_code"] = parsed.country_code
            findings["international_format"] = phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
            )
            findings["national_format"] = phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.NATIONAL
            )
            findings["e164_format"] = phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.E164
            )

            # Number type
            num_type = phonenumbers.number_type(parsed)
            type_map = {
                phonenumbers.PhoneNumberType.MOBILE: "Mobile",
                phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed Line",
                phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line or Mobile",
                phonenumbers.PhoneNumberType.TOLL_FREE: "Toll Free",
                phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium Rate",
                phonenumbers.PhoneNumberType.VOIP: "VoIP",
                phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Personal",
                phonenumbers.PhoneNumberType.PAGER: "Pager",
            }
            findings["phone_type"] = type_map.get(num_type, "Unknown")

            # Carrier
            findings["carrier"] = carrier.name_for_number(parsed, "en") or "Unknown"

            # Geo
            findings["country"] = geocoder.country_name_for_number(parsed, "en") or "Unknown"
            findings["region"] = geocoder.description_for_number(parsed, "en") or ""

            # Timezones
            findings["timezones"] = list(timezone.time_zones_for_number(parsed))

        except Exception as e:
            return ScanResult(
                module=self.name, target=target, success=False,
                error=str(e), summary=f"Failed to parse phone number: {target}",
            )

        entities = []
        if findings["valid"]:
            entities.append(EntityFound(
                entity_type="phone",
                value=findings["e164_format"],
                source=self.name,
                confidence=1.0,
                metadata={
                    "carrier": findings["carrier"],
                    "country": findings["country"],
                    "region": findings["region"],
                    "type": findings["phone_type"],
                },
            ))

            if findings["country"]:
                entities.append(EntityFound(
                    entity_type="location",
                    value=findings["country"],
                    source=self.name,
                    confidence=0.7,
                    metadata={"region": findings["region"]},
                    relationships=[{"type": "LOCATED_IN", "target": findings["e164_format"]}],
                ))

        summary = (
            f"Phone: {findings['international_format']} | "
            f"Valid: {'✓' if findings['valid'] else '✗'} | "
            f"Type: {findings['phone_type']} | "
            f"Carrier: {findings['carrier']} | "
            f"Country: {findings['country']}"
        )

        return ScanResult(
            module=self.name, target=target, success=True,
            entities=entities, raw_data=findings, summary=summary,
        )


ModuleRegistry.register(PhoneLookup())
