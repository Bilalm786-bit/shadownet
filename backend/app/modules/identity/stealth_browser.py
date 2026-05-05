"""
ShadowNet — Stealth Browser Module
Playwright-based stealth browser for scraping JS-heavy platforms
(Instagram, Facebook, LinkedIn) that block simple HTTP requests.
Falls back to aiohttp if Playwright is not installed.
"""

import asyncio
import re
from typing import Dict, Any, List, Optional
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry
import structlog

logger = structlog.get_logger(__name__)

try:
    from playwright.async_api import async_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False
    logger.info("Playwright not installed — stealth browser disabled, using aiohttp fallback")


class StealthBrowser(OSINTModule):
    name = "identity.stealth_browser"
    description = "Playwright stealth browser — scrapes JS-rendered social profiles (Instagram, Facebook, LinkedIn)"
    supported_target_types = ["username", "email", "person"]
    requires_api_key = False
    rate_limit = 3

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        target = target.strip()
        entities = []
        profiles = []
        errors = []
        is_email = "@" in target
        username = target.split("@")[0] if is_email else target

        if HAS_PLAYWRIGHT:
            try:
                async with async_playwright() as pw:
                    browser = await pw.chromium.launch(
                        headless=True,
                        args=["--no-sandbox", "--disable-blink-features=AutomationControlled",
                              "--disable-dev-shm-usage", "--disable-gpu"]
                    )
                    context = await browser.new_context(
                        viewport={"width": 1920, "height": 1080},
                        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                        locale="en-US",
                        timezone_id="America/New_York",
                    )
                    # Stealth: remove webdriver flag
                    await context.add_init_script("""
                        Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
                        Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
                        Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
                        window.chrome = { runtime: {} };
                    """)
                    page = await context.new_page()

                    # Scrape Instagram
                    ig = await self._pw_instagram(page, username)
                    if ig:
                        profiles.append(ig)

                    # Scrape Facebook
                    fb = await self._pw_facebook(page, username)
                    if fb:
                        profiles.append(fb)

                    # Scrape LinkedIn
                    li = await self._pw_linkedin(page, target)
                    if li:
                        profiles.append(li)

                    # Scrape Twitter/X
                    tw = await self._pw_twitter(page, username)
                    if tw:
                        profiles.append(tw)

                    await browser.close()

            except Exception as e:
                errors.append(f"Playwright browser error: {str(e)}")
                logger.warning("Stealth browser failed, results may be limited", error=str(e))
        else:
            # Fallback: use aiohttp for basic scraping
            import aiohttp
            connector = aiohttp.TCPConnector(limit=5, ssl=False)
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            }
            async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
                ig = await self._http_instagram(session, username)
                if ig:
                    profiles.append(ig)
                fb = await self._http_facebook(session, username)
                if fb:
                    profiles.append(fb)

        # Build entities from profiles
        cross_ref = {"names": set(), "locations": set(), "emails": set()}
        for profile in profiles:
            data = profile.get("data", {})
            entities.append(EntityFound(
                entity_type="social_profile", value=profile.get("url", ""),
                source=self.name, confidence=profile.get("confidence", 0.85),
                metadata={
                    "platform": profile["platform"], "username": username,
                    "display_name": data.get("name", ""), "bio": data.get("bio", ""),
                    "followers": data.get("followers", ""), "following": data.get("following", ""),
                    "posts_count": data.get("posts_count", ""), "verified": data.get("verified", False),
                    "is_private": data.get("is_private", False), "avatar_url": data.get("avatar", ""),
                    "extraction_method": profile.get("method", "stealth_browser"),
                },
                relationships=[{"type": "HAS_PROFILE", "target": target}],
            ))
            if data.get("name"):
                cross_ref["names"].add(data["name"])
            if data.get("location"):
                cross_ref["locations"].add(data["location"])

        for name in cross_ref["names"]:
            entities.append(EntityFound(entity_type="person", value=name, source=self.name, confidence=0.85,
                                        metadata={"derived_from": "stealth_browser"},
                                        relationships=[{"type": "REAL_NAME_OF", "target": target}]))

        severity = "high" if len(profiles) >= 3 else "medium" if profiles else "low"
        method = "Playwright" if HAS_PLAYWRIGHT else "HTTP fallback"
        summary = f"Stealth browser ({method}) for '{target}': {len(profiles)} profiles scraped"

        return ScanResult(
            module=self.name, target=target, success=True, entities=entities,
            raw_data={"profiles": profiles, "method": method, "errors": errors},
            summary=summary, severity=severity,
        )

    # ── Playwright scrapers ──────────────────────────────────

    async def _pw_instagram(self, page, username: str) -> Optional[Dict]:
        try:
            await page.goto(f"https://www.instagram.com/{username}/", wait_until="domcontentloaded", timeout=15000)
            await asyncio.sleep(2)
            content = await page.content()
            if "Sorry, this page" in content or "Page Not Found" in content:
                return None
            # Extract from meta tags and JSON
            name = await self._extract_meta(page, "og:title")
            desc = await self._extract_meta(page, "og:description")
            avatar = await self._extract_meta(page, "og:image")
            # Parse follower counts from description
            followers = following = posts = ""
            if desc:
                f_match = re.search(r'([\d,.]+[KM]?)\s*Followers', desc)
                fw_match = re.search(r'([\d,.]+[KM]?)\s*Following', desc)
                p_match = re.search(r'([\d,.]+[KM]?)\s*Posts', desc)
                followers = f_match.group(1) if f_match else ""
                following = fw_match.group(1) if fw_match else ""
                posts = p_match.group(1) if p_match else ""

            if name or desc:
                return {
                    "platform": "Instagram", "url": f"https://www.instagram.com/{username}/",
                    "method": "playwright_stealth", "confidence": 0.92,
                    "data": {
                        "name": name.split("(")[0].strip() if name else "",
                        "bio": desc[:200] if desc else "",
                        "avatar": avatar or "", "followers": followers,
                        "following": following, "posts_count": posts,
                    },
                }
        except Exception as e:
            logger.debug("PW Instagram failed", error=str(e))
        return None

    async def _pw_facebook(self, page, username: str) -> Optional[Dict]:
        try:
            await page.goto(f"https://www.facebook.com/{username}", wait_until="domcontentloaded", timeout=15000)
            await asyncio.sleep(2)
            content = await page.content()
            if "page not found" in content.lower() or "this content isn" in content.lower():
                return None
            name = await self._extract_meta(page, "og:title")
            desc = await self._extract_meta(page, "og:description")
            avatar = await self._extract_meta(page, "og:image")
            if name:
                return {
                    "platform": "Facebook", "url": f"https://www.facebook.com/{username}",
                    "method": "playwright_stealth", "confidence": 0.85,
                    "data": {"name": name.replace(" | Facebook", "").strip(), "bio": desc[:200] if desc else "", "avatar": avatar or ""},
                }
        except Exception as e:
            logger.debug("PW Facebook failed", error=str(e))
        return None

    async def _pw_linkedin(self, page, target: str) -> Optional[Dict]:
        try:
            # Search Google for LinkedIn profile
            await page.goto(f"https://www.google.com/search?q={target}+site:linkedin.com/in/", wait_until="domcontentloaded", timeout=15000)
            await asyncio.sleep(2)
            links = await page.query_selector_all("a")
            for link in links[:10]:
                href = await link.get_attribute("href") or ""
                if "linkedin.com/in/" in href:
                    url_match = re.search(r'(https?://[a-z]+\.linkedin\.com/in/[a-zA-Z0-9_-]+)', href)
                    if url_match:
                        text = await link.inner_text()
                        parts = text.split(" - ")
                        return {
                            "platform": "LinkedIn", "url": url_match.group(1),
                            "method": "playwright_google_extract", "confidence": 0.8,
                            "data": {"name": parts[0].strip() if parts else "", "bio": parts[1].strip() if len(parts) > 1 else ""},
                        }
        except Exception as e:
            logger.debug("PW LinkedIn failed", error=str(e))
        return None

    async def _pw_twitter(self, page, username: str) -> Optional[Dict]:
        # Try nitter instances first
        nitter_urls = [f"https://nitter.net/{username}", f"https://nitter.privacydev.net/{username}"]
        for nitter_url in nitter_urls:
            try:
                await page.goto(nitter_url, wait_until="domcontentloaded", timeout=12000)
                await asyncio.sleep(1.5)
                content = await page.content()
                if "User not found" in content or "Error" in content[:500]:
                    continue
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(content, "html.parser")
                name_el = soup.select_one(".profile-card-fullname")
                bio_el = soup.select_one(".profile-bio")
                if name_el:
                    stats = soup.select(".profile-stat-num")
                    return {
                        "platform": "Twitter/X", "url": f"https://x.com/{username}",
                        "method": "playwright_nitter", "confidence": 0.88,
                        "data": {
                            "name": name_el.get_text(strip=True),
                            "bio": bio_el.get_text(strip=True) if bio_el else "",
                            "posts_count": stats[0].get_text(strip=True) if stats and len(stats) > 0 else "",
                            "following": stats[1].get_text(strip=True) if stats and len(stats) > 1 else "",
                            "followers": stats[2].get_text(strip=True) if stats and len(stats) > 2 else "",
                        },
                    }
            except Exception:
                continue
        return None

    # ── HTTP fallbacks ──────────────────────────────────────

    async def _http_instagram(self, session, username: str) -> Optional[Dict]:
        try:
            async with session.get(f"https://www.instagram.com/{username}/", timeout=aiohttp.ClientTimeout(total=12)) as resp:
                if resp.status == 200:
                    html = await resp.text()
                    if "Sorry, this page" not in html:
                        desc = re.search(r'<meta\s+property="og:description"\s+content="([^"]*)"', html)
                        title = re.search(r'<meta\s+property="og:title"\s+content="([^"]*)"', html)
                        if desc or title:
                            return {
                                "platform": "Instagram", "url": f"https://www.instagram.com/{username}/",
                                "method": "http_og_meta", "confidence": 0.75,
                                "data": {"name": title.group(1).split("(")[0].strip() if title else "", "bio": desc.group(1)[:200] if desc else ""},
                            }
        except Exception:
            pass
        return None

    async def _http_facebook(self, session, username: str) -> Optional[Dict]:
        try:
            async with session.get(f"https://www.facebook.com/{username}", timeout=aiohttp.ClientTimeout(total=12), allow_redirects=True) as resp:
                if resp.status == 200:
                    html = await resp.text()
                    title = re.search(r'<meta\s+property="og:title"\s+content="([^"]*)"', html)
                    if title:
                        return {
                            "platform": "Facebook", "url": f"https://www.facebook.com/{username}",
                            "method": "http_og_meta", "confidence": 0.7,
                            "data": {"name": title.group(1).replace(" | Facebook", "").strip()},
                        }
        except Exception:
            pass
        return None

    async def _extract_meta(self, page, prop: str) -> str:
        try:
            el = await page.query_selector(f'meta[property="{prop}"]')
            if el:
                return await el.get_attribute("content") or ""
        except Exception:
            pass
        return ""


ModuleRegistry.register(StealthBrowser())
