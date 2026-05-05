"""
ShadowNet — Phone Number Lookup Module (v2 — Enhanced)
Carrier detection, geo-location, format validation PLUS online enrichment:
  - Truecaller-style lookup via Google search
  - WhatsApp profile check
  - Telegram username lookup
  - Google dorking for phone number mentions
  - Social media association search
NO API key — uses phonenumbers library + stealth web scraping.
"""

import phonenumbers
from phonenumbers import carrier, geocoder, timezone
import aiohttp
import asyncio
import re
from typing import Dict, Any, List
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry
import structlog

logger = structlog.get_logger(__name__)

STEALTH_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "DNT": "1",
}


class PhoneLookup(OSINTModule):
    name = "identity.phone_lookup"
    description = "Phone validation, carrier, geolocation + online enrichment (Truecaller, WhatsApp, Telegram, Google dork)"
    supported_target_types = ["phone"]
    requires_api_key = False
    rate_limit = 5

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        phone = target.strip()
        entities = []
        findings = {
            "input": phone, "valid": False, "possible": False,
            "phone_type": "", "carrier": "", "country": "", "region": "",
            "timezones": [], "international_format": "", "national_format": "",
            "e164_format": "", "country_code": None,
        }

        # Phase 1: Offline parsing with libphonenumber
        try:
            if not phone.startswith("+"):
                phone = "+" + phone
            parsed = phonenumbers.parse(phone, None)

            findings["valid"] = phonenumbers.is_valid_number(parsed)
            findings["possible"] = phonenumbers.is_possible_number(parsed)
            findings["country_code"] = parsed.country_code
            findings["international_format"] = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
            findings["national_format"] = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
            findings["e164_format"] = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)

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
            findings["carrier"] = carrier.name_for_number(parsed, "en") or "Unknown"
            findings["country"] = geocoder.country_name_for_number(parsed, "en") or "Unknown"
            findings["region"] = geocoder.description_for_number(parsed, "en") or ""
            findings["timezones"] = list(timezone.time_zones_for_number(parsed))

        except Exception as e:
            return ScanResult(
                module=self.name, target=target, success=False,
                error=str(e), summary=f"Failed to parse phone number: {target}",
            )

        # Phase 2: Online enrichment
        online_results = {"google_mentions": [], "whatsapp": None, "telegram": None, "truecaller_hints": [], "social_links": []}
        if findings["valid"]:
            connector = aiohttp.TCPConnector(limit=5, ssl=False)
            async with aiohttp.ClientSession(connector=connector, headers=STEALTH_HEADERS) as session:
                tasks = {
                    "google": self._google_phone_search(session, findings["international_format"], findings["e164_format"]),
                    "whatsapp": self._check_whatsapp(session, findings["e164_format"]),
                    "telegram": self._check_telegram(session, findings["e164_format"]),
                    "truecaller": self._truecaller_search(session, findings["international_format"]),
                    "social": self._social_phone_search(session, findings["international_format"]),
                }
                keys = list(tasks.keys())
                results = await asyncio.gather(*tasks.values(), return_exceptions=True)
                for key, result in zip(keys, results):
                    if isinstance(result, Exception):
                        logger.debug(f"Phone online {key} failed", error=str(result))
                    elif result:
                        online_results[key] = result

        findings["online"] = online_results

        # Build entities
        if findings["valid"]:
            entities.append(EntityFound(
                entity_type="phone", value=findings["e164_format"],
                source=self.name, confidence=1.0,
                metadata={
                    "carrier": findings["carrier"], "country": findings["country"],
                    "region": findings["region"], "type": findings["phone_type"],
                    "has_whatsapp": bool(online_results.get("whatsapp")),
                    "has_telegram": bool(online_results.get("telegram")),
                },
            ))
            if findings["country"]:
                entities.append(EntityFound(
                    entity_type="location", value=findings["country"],
                    source=self.name, confidence=0.7,
                    metadata={"region": findings["region"]},
                    relationships=[{"type": "LOCATED_IN", "target": findings["e164_format"]}],
                ))

            # WhatsApp entity
            wa = online_results.get("whatsapp")
            if wa and wa.get("exists"):
                entities.append(EntityFound(
                    entity_type="messaging_account", value=f"WhatsApp: {findings['e164_format']}",
                    source=self.name, confidence=0.8,
                    metadata={"platform": "WhatsApp", "name": wa.get("name", ""), "avatar": wa.get("avatar", "")},
                    relationships=[{"type": "HAS_WHATSAPP", "target": findings["e164_format"]}],
                ))

            # Telegram entity
            tg = online_results.get("telegram")
            if tg and tg.get("exists"):
                entities.append(EntityFound(
                    entity_type="messaging_account", value=f"Telegram: {tg.get('username', findings['e164_format'])}",
                    source=self.name, confidence=0.75,
                    metadata={"platform": "Telegram", "username": tg.get("username", "")},
                    relationships=[{"type": "HAS_TELEGRAM", "target": findings["e164_format"]}],
                ))

            # Google mention entities
            for mention in online_results.get("google_mentions", online_results.get("google", [])):
                if isinstance(mention, dict):
                    entities.append(EntityFound(
                        entity_type="phone_mention", value=mention.get("url", ""),
                        source=self.name, confidence=0.6,
                        metadata={"title": mention.get("title", ""), "source": "Google"},
                        relationships=[{"type": "PHONE_MENTIONED_IN", "target": findings["e164_format"]}],
                    ))

            # Social link entities
            for link in online_results.get("social", online_results.get("social_links", [])):
                if isinstance(link, dict):
                    entities.append(EntityFound(
                        entity_type="social_profile", value=link.get("url", ""),
                        source=self.name, confidence=0.5,
                        metadata={"platform": link.get("platform", ""), "derived_from": "phone_search"},
                        relationships=[{"type": "PHONE_LINKED", "target": findings["e164_format"]}],
                    ))

        wa_status = "✓" if online_results.get("whatsapp", {}).get("exists") else "✗"
        tg_status = "✓" if online_results.get("telegram", {}).get("exists") else "✗"
        google_count = len(online_results.get("google", []))

        summary = (
            f"Phone: {findings['international_format']} | "
            f"Valid: {'✓' if findings['valid'] else '✗'} | "
            f"Type: {findings['phone_type']} | Carrier: {findings['carrier']} | "
            f"Country: {findings['country']} | "
            f"WhatsApp: {wa_status} | Telegram: {tg_status} | "
            f"Google mentions: {google_count}"
        )

        severity = "medium" if google_count > 0 or online_results.get("whatsapp") else "low"

        return ScanResult(
            module=self.name, target=target, success=True,
            entities=entities, raw_data=findings, summary=summary, severity=severity,
        )

    async def _google_phone_search(self, session, intl_format: str, e164: str) -> List[Dict]:
        """Google search for phone number mentions."""
        results = []
        try:
            from googlesearch import search as gsearch
            loop = asyncio.get_event_loop()
            queries = [f'"{intl_format}"', f'"{e164}" -site:facebook.com -site:instagram.com']
            for query in queries:
                try:
                    urls = await loop.run_in_executor(None, lambda q=query: list(gsearch(q, num_results=5, sleep_interval=2)))
                    for url in urls:
                        results.append({"url": url, "query": query, "title": ""})
                    await asyncio.sleep(1.5)
                except Exception:
                    continue
        except ImportError:
            pass
        return results

    async def _check_whatsapp(self, session, e164: str) -> Dict:
        """Check WhatsApp presence via web endpoint."""
        try:
            phone_clean = e164.replace("+", "")
            async with session.get(
                f"https://wa.me/{phone_clean}",
                timeout=aiohttp.ClientTimeout(total=10),
                allow_redirects=True,
            ) as resp:
                if resp.status == 200:
                    html = await resp.text()
                    if "Chat on WhatsApp" in html or "api.whatsapp.com" in html:
                        return {"exists": True, "url": f"https://wa.me/{phone_clean}"}
                    if "number is not" in html.lower() or "invalid" in html.lower():
                        return {"exists": False}
            return {"exists": False}
        except Exception:
            return {"exists": False}

    async def _check_telegram(self, session, e164: str) -> Dict:
        """Check Telegram presence."""
        try:
            # Try t.me phone check
            phone_clean = e164.replace("+", "")
            async with session.get(
                f"https://t.me/+{phone_clean}",
                timeout=aiohttp.ClientTimeout(total=10),
                allow_redirects=True,
            ) as resp:
                if resp.status == 200:
                    html = await resp.text()
                    if "tgme_page_title" in html:
                        from bs4 import BeautifulSoup
                        soup = BeautifulSoup(html, "html.parser")
                        title = soup.select_one(".tgme_page_title")
                        if title:
                            return {"exists": True, "username": title.get_text(strip=True)}
            return {"exists": False}
        except Exception:
            return {"exists": False}

    async def _truecaller_search(self, session, intl_format: str) -> List[Dict]:
        """Search for Truecaller cached results via Google."""
        results = []
        try:
            from googlesearch import search as gsearch
            loop = asyncio.get_event_loop()
            query = f'"{intl_format}" site:truecaller.com OR "caller ID" OR "who called"'
            urls = await loop.run_in_executor(None, lambda: list(gsearch(query, num_results=3, sleep_interval=2)))
            for url in urls:
                results.append({"url": url, "source": "Truecaller/CallerID search"})
        except ImportError:
            pass
        except Exception:
            pass
        return results

    async def _social_phone_search(self, session, intl_format: str) -> List[Dict]:
        """Search social platforms for phone number associations."""
        results = []
        try:
            from googlesearch import search as gsearch
            loop = asyncio.get_event_loop()
            query = f'"{intl_format}" (site:facebook.com OR site:linkedin.com OR site:twitter.com)'
            urls = await loop.run_in_executor(None, lambda: list(gsearch(query, num_results=5, sleep_interval=2)))
            for url in urls:
                platform = "Unknown"
                if "facebook" in url:
                    platform = "Facebook"
                elif "linkedin" in url:
                    platform = "LinkedIn"
                elif "twitter" in url or "x.com" in url:
                    platform = "Twitter/X"
                results.append({"url": url, "platform": platform})
        except ImportError:
            pass
        except Exception:
            pass
        return results


ModuleRegistry.register(PhoneLookup())
