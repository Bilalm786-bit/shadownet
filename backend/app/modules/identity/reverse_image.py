"""
ShadowNet — Reverse Image Search & EXIF Extraction Module
Performs reverse image lookups using Yandex, TinEye, and Google Lens.
Extracts EXIF metadata (GPS, device, timestamps) from downloaded images.
NO API key required.
"""

import aiohttp
import asyncio
import re
import hashlib
from typing import Dict, Any, List, Optional
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry
import structlog

logger = structlog.get_logger(__name__)

try:
    import exifread
    HAS_EXIF = True
except ImportError:
    HAS_EXIF = False

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    import io
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


def _dms_to_decimal(dms_values, ref: str) -> Optional[float]:
    try:
        if hasattr(dms_values[0], 'num'):
            d = float(dms_values[0].num) / float(dms_values[0].den)
            m = float(dms_values[1].num) / float(dms_values[1].den)
            s = float(dms_values[2].num) / float(dms_values[2].den)
        else:
            d, m, s = float(dms_values[0]), float(dms_values[1]), float(dms_values[2])
        decimal = d + m / 60 + s / 3600
        if ref in ('S', 'W'):
            decimal = -decimal
        return round(decimal, 6)
    except Exception:
        return None


class ReverseImageSearch(OSINTModule):
    name = "identity.reverse_image"
    description = "Reverse image search + EXIF GPS/device extraction (free, no key)"
    supported_target_types = ["image_url", "person"]
    requires_api_key = False
    rate_limit = 3

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        options = options or {}
        entities, image_urls = [], []

        if target.startswith("http"):
            image_urls.append(target)
        avatar_urls = options.get("avatar_urls", [])
        if isinstance(avatar_urls, list):
            image_urls.extend(avatar_urls)
        elif isinstance(avatar_urls, str) and avatar_urls:
            image_urls.append(avatar_urls)

        if not image_urls:
            return ScanResult(
                module=self.name, target=target, success=True,
                summary=f"No image URLs for '{target}'",
                raw_data={"note": "Pass image URLs via options.avatar_urls"},
                severity="info",
            )

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        }
        connector = aiohttp.TCPConnector(limit=5, ssl=False)
        all_matches, exif_results = [], []

        async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
            for img_url in image_urls[:3]:
                exif_data = await self._extract_exif(session, img_url)
                if exif_data:
                    exif_results.append({"url": img_url, "exif": exif_data})
                yandex = await self._yandex_reverse_search(session, img_url)
                all_matches.extend(yandex)
                tineye = await self._tineye_search(session, img_url)
                all_matches.extend(tineye)
                all_matches.append({"source": "Google Lens", "url": f"https://lens.google.com/uploadbyurl?url={img_url}", "title": "Google Lens (manual)", "type": "search_link"})
                await asyncio.sleep(1)

        for exif_item in exif_results:
            exif = exif_item["exif"]
            if exif.get("gps_lat") and exif.get("gps_lon"):
                entities.append(EntityFound(
                    entity_type="geolocation", value=f"{exif['gps_lat']}, {exif['gps_lon']}",
                    source=self.name, confidence=0.95,
                    metadata={"latitude": exif["gps_lat"], "longitude": exif["gps_lon"], "image_url": exif_item["url"], "google_maps": f"https://maps.google.com/?q={exif['gps_lat']},{exif['gps_lon']}"},
                    relationships=[{"type": "PHOTO_TAKEN_AT", "target": target}],
                ))
            if exif.get("device"):
                entities.append(EntityFound(
                    entity_type="device", value=exif["device"], source=self.name, confidence=0.9,
                    metadata={"model": exif.get("model", ""), "software": exif.get("software", ""), "datetime": exif.get("datetime", "")},
                    relationships=[{"type": "PHOTO_TAKEN_WITH", "target": target}],
                ))
            entities.append(EntityFound(entity_type="image_metadata", value=exif_item["url"], source=self.name, confidence=0.9, metadata=exif))

        seen_urls = set()
        for match in all_matches:
            url = match.get("url", "")
            if url and url not in seen_urls and match.get("type") != "search_link":
                seen_urls.add(url)
                entities.append(EntityFound(
                    entity_type="image_match", value=url, source=self.name, confidence=match.get("confidence", 0.6),
                    metadata={"title": match.get("title", ""), "search_engine": match.get("source", "")},
                    relationships=[{"type": "IMAGE_APPEARS_ON", "target": target}],
                ))

        has_gps = any(e.get("exif", {}).get("gps_lat") for e in exif_results)
        severity = "high" if has_gps else "medium" if all_matches else "info"
        summary = f"Reverse image for '{target}': {len(image_urls)} images | {len(all_matches)} matches | GPS: {'YES' if has_gps else 'No'}"

        return ScanResult(
            module=self.name, target=target, success=True, entities=entities,
            raw_data={"image_urls_searched": image_urls, "matches": all_matches, "exif_data": exif_results},
            summary=summary, severity=severity,
        )

    async def _extract_exif(self, session, image_url: str) -> Optional[Dict]:
        try:
            async with session.get(image_url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    return None
                image_data = await resp.read()
                if len(image_data) > 20 * 1024 * 1024:
                    return None
                exif_info = {}
                if HAS_EXIF:
                    import io as _io
                    tags = exifread.process_file(_io.BytesIO(image_data), details=False)
                    if tags:
                        gps_lat = tags.get("GPS GPSLatitude")
                        gps_lat_ref = tags.get("GPS GPSLatitudeRef")
                        gps_lon = tags.get("GPS GPSLongitude")
                        gps_lon_ref = tags.get("GPS GPSLongitudeRef")
                        if gps_lat and gps_lon:
                            lat = _dms_to_decimal(gps_lat.values, str(gps_lat_ref))
                            lon = _dms_to_decimal(gps_lon.values, str(gps_lon_ref))
                            if lat and lon:
                                exif_info["gps_lat"] = lat
                                exif_info["gps_lon"] = lon
                        make = str(tags.get("Image Make", ""))
                        model = str(tags.get("Image Model", ""))
                        if make or model:
                            exif_info["device"] = f"{make} {model}".strip()
                            exif_info["make"] = make
                            exif_info["model"] = model
                        exif_info["software"] = str(tags.get("Image Software", ""))
                        exif_info["datetime"] = str(tags.get("EXIF DateTimeOriginal", tags.get("Image DateTime", "")))
                exif_info["sha256"] = hashlib.sha256(image_data).hexdigest()
                exif_info["file_size"] = len(image_data)
                return exif_info if exif_info else None
        except Exception as e:
            logger.debug("EXIF extraction failed", error=str(e))
            return None

    async def _yandex_reverse_search(self, session, image_url: str) -> List[Dict]:
        results = []
        try:
            search_url = f"https://yandex.com/images/search?rpt=imageview&url={image_url}"
            async with session.get(search_url, headers={"Referer": "https://yandex.com/images/"}, timeout=aiohttp.ClientTimeout(total=15), allow_redirects=True) as resp:
                if resp.status == 200:
                    from bs4 import BeautifulSoup
                    html = await resp.text()
                    soup = BeautifulSoup(html, "html.parser")
                    for item in soup.select(".CbirSites-Item, .other-sites__item")[:10]:
                        link = item.select_one("a")
                        title_el = item.select_one(".CbirSites-ItemTitle, .other-sites__title")
                        if link:
                            results.append({"source": "Yandex", "url": link.get("href", ""), "title": title_el.get_text(strip=True) if title_el else "", "type": "image_match", "confidence": 0.75})
                    for tag in soup.select(".CbirTags-Button, .tags__item")[:5]:
                        tag_text = tag.get_text(strip=True)
                        if tag_text and len(tag_text) > 2:
                            results.append({"source": "Yandex Tags", "url": f"https://yandex.com/images/search?text={tag_text}", "title": f"Tag: {tag_text}", "type": "identity_tag", "confidence": 0.6})
            results.append({"source": "Yandex", "url": f"https://yandex.com/images/search?rpt=imageview&url={image_url}", "title": "Yandex full results", "type": "search_link"})
        except Exception as e:
            logger.debug("Yandex reverse search failed", error=str(e))
        return results

    async def _tineye_search(self, session, image_url: str) -> List[Dict]:
        results = []
        try:
            search_url = f"https://tineye.com/search?url={image_url}"
            async with session.get(search_url, timeout=aiohttp.ClientTimeout(total=15), allow_redirects=True) as resp:
                if resp.status == 200:
                    from bs4 import BeautifulSoup
                    html = await resp.text()
                    soup = BeautifulSoup(html, "html.parser")
                    for item in soup.select(".match, .result")[:10]:
                        link = item.select_one("a.image-link, a")
                        domain_el = item.select_one(".match-domain, .domain")
                        if link:
                            results.append({"source": "TinEye", "url": link.get("href", ""), "title": domain_el.get_text(strip=True) if domain_el else "", "type": "image_match", "confidence": 0.8})
            results.append({"source": "TinEye", "url": search_url, "title": "TinEye full results", "type": "search_link"})
        except Exception as e:
            logger.debug("TinEye search failed", error=str(e))
        return results


ModuleRegistry.register(ReverseImageSearch())
