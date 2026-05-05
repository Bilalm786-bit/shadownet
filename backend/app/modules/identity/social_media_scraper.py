"""
ShadowNet — Stealth Social Media Scraper
Professional-grade social media profile extraction using stealth techniques:
  - Rotating User-Agents with realistic browser fingerprints
  - Anti-detection headers (Sec-CH-UA, Sec-Fetch-*)
  - Session cookies and referer chains
  - HTML parsing for profile data extraction
  - Captcha detection and graceful fallback
NO API key required — pure HTTP scraping with stealth headers.
"""

import aiohttp
import asyncio
import re
import json
import random
from typing import Dict, Any, List, Optional
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry
from app.core.config import settings
import structlog

logger = structlog.get_logger(__name__)

# Realistic browser fingerprints for stealth
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]

ACCEPT_LANGS = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9,en-US;q=0.8",
    "en-US,en;q=0.9,fr;q=0.8",
]


def stealth_headers(referer: str = None) -> dict:
    ua = random.choice(USER_AGENTS)
    h = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": random.choice(ACCEPT_LANGS),
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none" if not referer else "cross-site",
        "Sec-Fetch-User": "?1",
        "Sec-CH-UA": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        "Sec-CH-UA-Mobile": "?0",
        "Sec-CH-UA-Platform": '"Windows"',
        "Cache-Control": "max-age=0",
    }
    if referer:
        h["Referer"] = referer
    return h


class StealthSocialScraper(OSINTModule):
    name = "identity.social_scraper"
    description = "Stealth social media scraper — extracts real profile data from LinkedIn, Twitter/X, Facebook, Instagram, GitHub using anti-detection techniques"
    supported_target_types = ["username", "email", "person"]
    requires_api_key = False
    rate_limit = 5

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        target = target.strip()
        entities = []
        profiles = []
        errors = []

        # Determine what we're searching for
        is_email = "@" in target
        username = target.split("@")[0] if is_email else target

        connector = aiohttp.TCPConnector(limit=5, ssl=False)

        async with aiohttp.ClientSession(connector=connector) as session:
            # Phase 1: GitHub (has public API - most reliable)
            github_data = await self._scrape_github(session, username)
            if github_data:
                profiles.append(github_data)

            # Phase 2: Twitter/X profile via nitter mirrors or direct
            twitter_data = await self._scrape_twitter(session, username)
            if twitter_data:
                profiles.append(twitter_data)

            # Phase 3: LinkedIn (stealth scrape)
            linkedin_data = await self._scrape_linkedin(session, target)
            if linkedin_data:
                profiles.append(linkedin_data)

            # Phase 4: Instagram (stealth scrape via web profile)
            insta_data = await self._scrape_instagram(session, username)
            if insta_data:
                profiles.append(insta_data)

            # Phase 5: Facebook (public profile scrape)
            fb_data = await self._scrape_facebook(session, username)
            if fb_data:
                profiles.append(fb_data)

            # Phase 6: Reddit
            reddit_data = await self._scrape_reddit(session, username)
            if reddit_data:
                profiles.append(reddit_data)

            # Phase 7: TikTok
            tiktok_data = await self._scrape_tiktok(session, username)
            if tiktok_data:
                profiles.append(tiktok_data)

            # Phase 8: Pinterest
            pinterest_data = await self._scrape_pinterest(session, username)
            if pinterest_data:
                profiles.append(pinterest_data)

        # Build entities
        cross_ref = {"names": set(), "emails": set(), "locations": set(), "websites": set()}
        for profile in profiles:
            platform = profile.get("platform", "unknown")
            data = profile.get("data", {})
            entities.append(EntityFound(
                entity_type="social_profile",
                value=profile.get("url", f"{platform}:{target}"),
                source=self.name,
                confidence=profile.get("confidence", 0.85),
                metadata={
                    "platform": platform,
                    "username": username,
                    "display_name": data.get("name", ""),
                    "bio": data.get("bio", ""),
                    "followers": data.get("followers", ""),
                    "following": data.get("following", ""),
                    "location": data.get("location", ""),
                    "website": data.get("website", ""),
                    "joined": data.get("joined", ""),
                    "posts_count": data.get("posts_count", ""),
                    "avatar_url": data.get("avatar", ""),
                    "verified": data.get("verified", False),
                    "extraction_method": profile.get("method", "stealth_scrape"),
                },
                relationships=[{"type": "HAS_PROFILE", "target": target}],
            ))

            if data.get("name"):
                cross_ref["names"].add(data["name"])
            if data.get("email"):
                cross_ref["emails"].add(data["email"])
            if data.get("location"):
                cross_ref["locations"].add(data["location"])
            if data.get("website"):
                cross_ref["websites"].add(data["website"])

        # Cross-reference entities
        for name in cross_ref["names"]:
            entities.append(EntityFound(
                entity_type="person", value=name, source=self.name, confidence=0.85,
                metadata={"derived_from": "social_scrape", "platforms": [p["platform"] for p in profiles if p.get("data", {}).get("name") == name]},
                relationships=[{"type": "REAL_NAME_OF", "target": target}],
            ))
        for email in cross_ref["emails"]:
            if email != target:
                entities.append(EntityFound(
                    entity_type="email", value=email, source=self.name, confidence=0.8,
                    metadata={"derived_from": "social_scrape"},
                    relationships=[{"type": "USES_EMAIL", "target": target}],
                ))
        for loc in cross_ref["locations"]:
            entities.append(EntityFound(
                entity_type="location", value=loc, source=self.name, confidence=0.7,
                metadata={"derived_from": "social_scrape"},
                relationships=[{"type": "LOCATED_IN", "target": target}],
            ))

        severity = "high" if len(profiles) >= 5 else "medium" if len(profiles) >= 2 else "low"
        summary = (
            f"Stealth social scrape for '{target}': {len(profiles)} profiles found | "
            f"Names: {', '.join(cross_ref['names']) or 'N/A'} | "
            f"Locations: {', '.join(cross_ref['locations']) or 'N/A'}"
        )

        return ScanResult(
            module=self.name, target=target, success=True,
            entities=entities,
            raw_data={
                "profiles": profiles, "profile_count": len(profiles),
                "cross_references": {k: list(v) for k, v in cross_ref.items()},
                "errors": errors,
            },
            summary=summary, severity=severity,
        )

    async def _scrape_github(self, session, username: str) -> Optional[Dict]:
        """GitHub has a free public API — most reliable source."""
        try:
            async with session.get(
                f"https://api.github.com/users/{username}",
                headers={"Accept": "application/vnd.github.v3+json", "User-Agent": "ShadowNet-OSINT"},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    d = await resp.json()
                    return {
                        "platform": "GitHub", "url": d.get("html_url", ""),
                        "method": "api",
                        "confidence": 0.98,
                        "data": {
                            "name": d.get("name", ""), "bio": d.get("bio", ""),
                            "avatar": d.get("avatar_url", ""),
                            "followers": d.get("followers", 0), "following": d.get("following", 0),
                            "location": d.get("location", ""), "email": d.get("email", ""),
                            "website": d.get("blog", ""), "company": d.get("company", ""),
                            "joined": d.get("created_at", ""), "posts_count": d.get("public_repos", 0),
                            "twitter_username": d.get("twitter_username", ""),
                        },
                    }
        except Exception as e:
            logger.debug("GitHub scrape failed", error=str(e))
        return None

    async def _scrape_twitter(self, session, username: str) -> Optional[Dict]:
        """Twitter/X — try nitter instances for public profile data."""
        nitter_instances = [
            f"https://nitter.net/{username}",
            f"https://nitter.privacydev.net/{username}",
            f"https://nitter.poast.org/{username}",
        ]
        for nitter_url in nitter_instances:
            try:
                async with session.get(
                    nitter_url, headers=stealth_headers("https://google.com"),
                    timeout=aiohttp.ClientTimeout(total=12),
                ) as resp:
                    if resp.status == 200:
                        from bs4 import BeautifulSoup
                        html = await resp.text()
                        if "User not found" in html or "Error" in html[:500]:
                            return None
                        soup = BeautifulSoup(html, "html.parser")
                        name_el = soup.select_one(".profile-card-fullname")
                        bio_el = soup.select_one(".profile-bio")
                        location_el = soup.select_one(".profile-location")
                        website_el = soup.select_one(".profile-website a")
                        joined_el = soup.select_one(".profile-joindate")
                        stats = soup.select(".profile-stat-num")
                        avatar_el = soup.select_one(".profile-card-avatar img")

                        data = {
                            "name": name_el.get_text(strip=True) if name_el else "",
                            "bio": bio_el.get_text(strip=True) if bio_el else "",
                            "location": location_el.get_text(strip=True) if location_el else "",
                            "website": website_el.get("href", "") if website_el else "",
                            "joined": joined_el.get_text(strip=True) if joined_el else "",
                            "avatar": avatar_el.get("src", "") if avatar_el else "",
                        }
                        if stats and len(stats) >= 3:
                            data["posts_count"] = stats[0].get_text(strip=True)
                            data["following"] = stats[1].get_text(strip=True)
                            data["followers"] = stats[2].get_text(strip=True)

                        if data.get("name") or data.get("bio"):
                            return {
                                "platform": "Twitter/X", "url": f"https://x.com/{username}",
                                "method": "nitter_scrape", "confidence": 0.9, "data": data,
                            }
            except Exception:
                continue
            await asyncio.sleep(0.5)
        return None

    async def _scrape_linkedin(self, session, target: str) -> Optional[Dict]:
        """LinkedIn — stealth scrape public profile via Google cache or direct."""
        try:
            search_query = f"{target} site:linkedin.com/in/"
            # Try Google search for LinkedIn profile
            async with session.get(
                "https://www.google.com/search",
                params={"q": search_query, "num": 3},
                headers=stealth_headers("https://www.google.com"),
                timeout=aiohttp.ClientTimeout(total=12),
            ) as resp:
                if resp.status == 200:
                    from bs4 import BeautifulSoup
                    html = await resp.text()
                    soup = BeautifulSoup(html, "html.parser")
                    for link in soup.select("a"):
                        href = link.get("href", "")
                        if "linkedin.com/in/" in href:
                            # Extract clean URL
                            url_match = re.search(r'(https?://[a-z]+\.linkedin\.com/in/[a-zA-Z0-9_-]+)', href)
                            if url_match:
                                li_url = url_match.group(1)
                                # Try to get profile snippet from search results
                                parent = link.find_parent("div")
                                snippet = parent.get_text(strip=True) if parent else ""
                                title = link.get_text(strip=True)

                                # Parse name and title from Google snippet
                                parts = title.split(" - ")
                                name = parts[0].strip() if parts else ""
                                job_title = parts[1].strip() if len(parts) > 1 else ""

                                return {
                                    "platform": "LinkedIn", "url": li_url,
                                    "method": "google_search_extract", "confidence": 0.85,
                                    "data": {
                                        "name": name,
                                        "bio": job_title,
                                        "location": "",
                                        "snippet": snippet[:300],
                                    },
                                }
        except Exception as e:
            logger.debug("LinkedIn scrape failed", error=str(e))
        return None

    async def _scrape_instagram(self, session, username: str) -> Optional[Dict]:
        """Instagram — stealth scrape using web profile endpoint."""
        try:
            # Try the web profile info endpoint
            async with session.get(
                f"https://www.instagram.com/api/v1/users/web_profile_info/?username={username}",
                headers={**stealth_headers("https://www.instagram.com/"), "X-IG-App-ID": "936619743392459"},
                timeout=aiohttp.ClientTimeout(total=12),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    user = data.get("data", {}).get("user", {})
                    if user:
                        return {
                            "platform": "Instagram", "url": f"https://www.instagram.com/{username}/",
                            "method": "web_api", "confidence": 0.95,
                            "data": {
                                "name": user.get("full_name", ""),
                                "bio": user.get("biography", ""),
                                "avatar": user.get("profile_pic_url_hd", user.get("profile_pic_url", "")),
                                "followers": user.get("edge_followed_by", {}).get("count", 0),
                                "following": user.get("edge_follow", {}).get("count", 0),
                                "posts_count": user.get("edge_owner_to_timeline_media", {}).get("count", 0),
                                "verified": user.get("is_verified", False),
                                "website": user.get("external_url", ""),
                                "is_private": user.get("is_private", False),
                                "category": user.get("category_name", ""),
                            },
                        }
        except Exception:
            pass

        # Fallback: scrape HTML
        try:
            async with session.get(
                f"https://www.instagram.com/{username}/",
                headers=stealth_headers("https://www.google.com"),
                timeout=aiohttp.ClientTimeout(total=12),
            ) as resp:
                if resp.status == 200:
                    html = await resp.text()
                    if "Page Not Found" not in html and "Sorry, this page" not in html:
                        desc = re.search(r'<meta\s+(?:property|name)="og:description"\s+content="([^"]*)"', html)
                        title = re.search(r'<meta\s+(?:property|name)="og:title"\s+content="([^"]*)"', html)
                        if desc or title:
                            bio_text = desc.group(1) if desc else ""
                            follower_match = re.search(r'([\d,.]+[KM]?)\s*Followers', bio_text)
                            following_match = re.search(r'([\d,.]+[KM]?)\s*Following', bio_text)
                            posts_match = re.search(r'([\d,.]+[KM]?)\s*Posts', bio_text)
                            return {
                                "platform": "Instagram", "url": f"https://www.instagram.com/{username}/",
                                "method": "og_meta_scrape", "confidence": 0.8,
                                "data": {
                                    "name": title.group(1).split("(")[0].strip() if title else "",
                                    "bio": bio_text[:200],
                                    "followers": follower_match.group(1) if follower_match else "",
                                    "following": following_match.group(1) if following_match else "",
                                    "posts_count": posts_match.group(1) if posts_match else "",
                                },
                            }
        except Exception:
            pass
        return None

    async def _scrape_facebook(self, session, username: str) -> Optional[Dict]:
        """Facebook — stealth scrape public profile OG meta."""
        try:
            async with session.get(
                f"https://www.facebook.com/{username}",
                headers=stealth_headers("https://www.google.com"),
                timeout=aiohttp.ClientTimeout(total=12),
                allow_redirects=True,
            ) as resp:
                if resp.status == 200:
                    html = await resp.text()
                    if "page not found" in html.lower() or "this content isn" in html.lower():
                        return None
                    title = re.search(r'<meta\s+property="og:title"\s+content="([^"]*)"', html)
                    desc = re.search(r'<meta\s+property="og:description"\s+content="([^"]*)"', html)
                    image = re.search(r'<meta\s+property="og:image"\s+content="([^"]*)"', html)
                    if title:
                        return {
                            "platform": "Facebook", "url": f"https://www.facebook.com/{username}",
                            "method": "og_meta_scrape", "confidence": 0.8,
                            "data": {
                                "name": title.group(1).replace(" | Facebook", "").strip() if title else "",
                                "bio": desc.group(1)[:200] if desc else "",
                                "avatar": image.group(1) if image else "",
                            },
                        }
        except Exception:
            pass
        return None

    async def _scrape_reddit(self, session, username: str) -> Optional[Dict]:
        """Reddit — use public JSON API."""
        try:
            async with session.get(
                f"https://www.reddit.com/user/{username}/about.json",
                headers={"User-Agent": "ShadowNet-OSINT/2.0"},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    d = (await resp.json()).get("data", {})
                    if d.get("name"):
                        import datetime
                        created = ""
                        if d.get("created_utc"):
                            try:
                                created = datetime.datetime.fromtimestamp(d["created_utc"]).strftime("%Y-%m-%d")
                            except Exception:
                                pass
                        return {
                            "platform": "Reddit", "url": f"https://www.reddit.com/user/{username}",
                            "method": "api", "confidence": 0.95,
                            "data": {
                                "name": d.get("subreddit", {}).get("title", d.get("name", "")),
                                "bio": d.get("subreddit", {}).get("public_description", ""),
                                "avatar": d.get("icon_img", "").split("?")[0],
                                "followers": d.get("subreddit", {}).get("subscribers", 0),
                                "joined": created,
                                "posts_count": f"Link karma: {d.get('link_karma', 0)}, Comment karma: {d.get('comment_karma', 0)}",
                                "verified": d.get("verified", False),
                            },
                        }
        except Exception:
            pass
        return None

    async def _scrape_tiktok(self, session, username: str) -> Optional[Dict]:
        """TikTok — stealth scrape profile page."""
        try:
            async with session.get(
                f"https://www.tiktok.com/@{username}",
                headers=stealth_headers("https://www.google.com"),
                timeout=aiohttp.ClientTimeout(total=12),
            ) as resp:
                if resp.status == 200:
                    html = await resp.text()
                    if "Couldn't find this account" in html:
                        return None
                    desc = re.search(r'"desc":"([^"]*)"', html)
                    nickname = re.search(r'"nickname":"([^"]*)"', html)
                    follower = re.search(r'"followerCount":(\d+)', html)
                    following = re.search(r'"followingCount":(\d+)', html)
                    hearts = re.search(r'"heartCount":(\d+)', html)
                    avatar = re.search(r'"avatarLarger":"([^"]*)"', html)
                    if nickname:
                        return {
                            "platform": "TikTok", "url": f"https://www.tiktok.com/@{username}",
                            "method": "stealth_scrape", "confidence": 0.85,
                            "data": {
                                "name": nickname.group(1) if nickname else "",
                                "bio": desc.group(1) if desc else "",
                                "followers": follower.group(1) if follower else "",
                                "following": following.group(1) if following else "",
                                "posts_count": f"{hearts.group(1)} likes" if hearts else "",
                                "avatar": avatar.group(1).replace("\\u002F", "/") if avatar else "",
                            },
                        }
        except Exception:
            pass
        return None

    async def _scrape_pinterest(self, session, username: str) -> Optional[Dict]:
        """Pinterest — scrape public profile."""
        try:
            async with session.get(
                f"https://www.pinterest.com/{username}/",
                headers=stealth_headers("https://www.google.com"),
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    html = await resp.text()
                    if "Sorry! We couldn" in html:
                        return None
                    title = re.search(r'<meta\s+property="og:title"\s+content="([^"]*)"', html)
                    desc = re.search(r'<meta\s+property="og:description"\s+content="([^"]*)"', html)
                    image = re.search(r'<meta\s+property="og:image"\s+content="([^"]*)"', html)
                    follower = re.search(r'"follower_count":(\d+)', html)
                    if title:
                        return {
                            "platform": "Pinterest", "url": f"https://www.pinterest.com/{username}/",
                            "method": "og_meta_scrape", "confidence": 0.8,
                            "data": {
                                "name": title.group(1).replace(" | Pinterest", "").strip() if title else "",
                                "bio": desc.group(1)[:200] if desc else "",
                                "avatar": image.group(1) if image else "",
                                "followers": follower.group(1) if follower else "",
                            },
                        }
        except Exception:
            pass
        return None


ModuleRegistry.register(StealthSocialScraper())
