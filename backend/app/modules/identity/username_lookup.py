"""
ShadowNet — Username Lookup Module (v2 — Reduced False Positives)
Sherlock-style username enumeration across 85+ platforms.
Uses content-based validation instead of just HTTP status codes.
NO API key required — uses direct HTTP requests.
"""

import aiohttp
import asyncio
import re
from typing import Dict, Any, List
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry


# Platform definitions with detection rules to reduce false positives.
# Each entry: { url, error_patterns (if any match body → NOT found), expected_type }
PLATFORMS = {
    "GitHub": {
        "url": "https://github.com/{}",
        "error_patterns": ["Not Found", "This is not the web page you are looking for"],
        "extract": {"bio": r'"description":"(.*?)"'},
    },
    "Twitter": {
        "url": "https://x.com/{}",
        "error_patterns": ["This account doesn", "doesn't exist", "Hmm...this page doesn"],
    },
    "Instagram": {
        "url": "https://www.instagram.com/{}/",
        "error_patterns": ["Sorry, this page isn't available", "Page Not Found"],
    },
    "Reddit": {
        "url": "https://www.reddit.com/user/{}/",
        "error_patterns": ["Sorry, nobody on Reddit goes by that name", "page not found"],
    },
    "TikTok": {
        "url": "https://www.tiktok.com/@{}",
        "error_patterns": ["Couldn't find this account", "couldn't find this page"],
    },
    "YouTube": {
        "url": "https://www.youtube.com/@{}",
        "error_patterns": ["404 Not Found", "This page isn't available"],
    },
    "Pinterest": {
        "url": "https://www.pinterest.com/{}/",
        "error_patterns": ["Sorry! We couldn", "Not Found"],
    },
    "Medium": {
        "url": "https://medium.com/@{}",
        "error_patterns": ["PAGE NOT FOUND", "404", "Out of nothing, something"],
    },
    "DeviantArt": {
        "url": "https://www.deviantart.com/{}",
        "error_patterns": ["The page you were looking for doesn"],
    },
    "SoundCloud": {
        "url": "https://soundcloud.com/{}",
        "error_patterns": ["We can't find that user", "404"],
    },
    "Twitch": {
        "url": "https://www.twitch.tv/{}",
        "error_patterns": ["Sorry. Unless you've got a time machine", "content is unavailable"],
    },
    "GitLab": {
        "url": "https://gitlab.com/{}",
        "error_patterns": ["Please sign in", "The page could not be found"],
    },
    "Keybase": {
        "url": "https://keybase.io/{}",
        "error_patterns": ["not found"],
    },
    "About.me": {
        "url": "https://about.me/{}",
        "error_patterns": ["page you requested was not found"],
    },
    "Dribbble": {
        "url": "https://dribbble.com/{}",
        "error_patterns": ["Whoops, that page is gone"],
    },
    "Behance": {
        "url": "https://www.behance.net/{}",
        "error_patterns": ["Oops! We can't find that page"],
    },
    "HackerRank": {
        "url": "https://www.hackerrank.com/{}",
        "error_patterns": ["Something went wrong", "page_not_found"],
    },
    "LeetCode": {
        "url": "https://leetcode.com/{}",
        "error_patterns": ["The page you are looking for", "doesn't exist"],
    },
    "Replit": {
        "url": "https://replit.com/@{}",
        "error_patterns": ["not found", "404"],
    },
    "Kaggle": {
        "url": "https://www.kaggle.com/{}",
        "error_patterns": ["404 - Page not found", "We couldn't find"],
    },
    "ProductHunt": {
        "url": "https://www.producthunt.com/@{}",
        "error_patterns": ["Page not found"],
    },
    "Mastodon": {
        "url": "https://mastodon.social/@{}",
        "error_patterns": ["The page you are looking for", "isn't here"],
    },
    "Telegram": {
        "url": "https://t.me/{}",
        "error_patterns": ["If you have Telegram", "can preview this"],
    },
    "Patreon": {
        "url": "https://www.patreon.com/{}",
        "error_patterns": ["404", "is creating"],
    },
    "Linktree": {
        "url": "https://linktr.ee/{}",
        "error_patterns": ["The page you're looking for", "Nothing to see here"],
    },
    "Vimeo": {
        "url": "https://vimeo.com/{}",
        "error_patterns": ["Sorry, we couldn't find that page"],
    },
    "Last.fm": {
        "url": "https://www.last.fm/user/{}",
        "error_patterns": ["Oops, we can't seem to find that"],
    },
    "Quora": {
        "url": "https://www.quora.com/profile/{}",
        "error_patterns": ["Page Not Found", "Something went wrong"],
    },
    "Chess.com": {
        "url": "https://www.chess.com/member/{}",
        "error_patterns": ["User Not Found", "Page not found"],
    },
    "Lichess": {
        "url": "https://lichess.org/@/{}",
        "error_patterns": ["Page not found"],
    },
    "Docker Hub": {
        "url": "https://hub.docker.com/u/{}",
        "error_patterns": ["HttpError", "404"],
    },
    "npm": {
        "url": "https://www.npmjs.com/~{}",
        "error_patterns": ["404", "page not found"],
    },
    "PyPI": {
        "url": "https://pypi.org/user/{}/",
        "error_patterns": ["Not Found"],
    },
    "Dev.to": {
        "url": "https://dev.to/{}",
        "error_patterns": ["Not Found"],
    },
    "CodePen": {
        "url": "https://codepen.io/{}",
        "error_patterns": ["404! That Page Doesn"],
    },
    "Gravatar": {
        "url": "https://en.gravatar.com/{}",
        "error_patterns": ["Profile not found"],
    },
    "HackerNews": {
        "url": "https://news.ycombinator.com/user?id={}",
        "error_patterns": ["No such user"],
    },
    "Steam": {
        "url": "https://steamcommunity.com/id/{}",
        "error_patterns": ["The specified profile could not be found"],
    },
    "Flickr": {
        "url": "https://www.flickr.com/people/{}/",
        "error_patterns": ["we couldn't find that page", "member not found"],
    },
    "Imgur": {
        "url": "https://imgur.com/user/{}",
        "error_patterns": ["Zoinks! You've taken a wrong turn"],
    },
    "Wattpad": {
        "url": "https://www.wattpad.com/user/{}",
        "error_patterns": ["Sorry, this page is missing"],
    },
    "Hashnode": {
        "url": "https://hashnode.com/@{}",
        "error_patterns": ["404"],
    },
    "StackOverflow": {
        "url": "https://stackoverflow.com/users/{}",
        "error_patterns": ["Page not found"],
        "no_content_check": True,  # Returns 404 directly for usernames
    },
    "Bitbucket": {
        "url": "https://bitbucket.org/{}/",
        "error_patterns": ["We couldn't find what you were looking for"],
    },
    "SlideShare": {
        "url": "https://www.slideshare.net/{}",
        "error_patterns": ["Page not found"],
    },
    "BuyMeACoffee": {
        "url": "https://buymeacoffee.com/{}",
        "error_patterns": ["Page Not Found", "404"],
    },
    "Substack": {
        "url": "https://{}.substack.com",
        "error_patterns": ["We couldn't find", "Page not found", "404"],
    },
    "Fiverr": {
        "url": "https://www.fiverr.com/{}",
        "error_patterns": ["was not found", "404"],
    },
    "OpenSea": {
        "url": "https://opensea.io/{}",
        "error_patterns": ["page doesn't exist"],
    },
    "9GAG": {
        "url": "https://9gag.com/u/{}",
        "error_patterns": ["User not found"],
    },
    "Mixcloud": {
        "url": "https://www.mixcloud.com/{}/",
        "error_patterns": ["Sorry, this page is not available"],
    },
    "Spotify": {
        "url": "https://open.spotify.com/user/{}",
        "error_patterns": [],
        "no_content_check": True,
    },
}


class UsernameLookup(OSINTModule):
    name = "identity.username_lookup"
    description = "Username enumeration across 50+ platforms with content-based validation (reduced false positives)"
    supported_target_types = ["username", "person"]
    requires_api_key = False
    rate_limit = 30

    async def _check_platform(
        self, session: aiohttp.ClientSession, platform: str, config: dict, username: str
    ) -> dict:
        """Check if a username exists on a specific platform with content validation."""
        try:
            full_url = config["url"].format(username)
            async with session.get(
                full_url,
                timeout=aiohttp.ClientTimeout(total=12),
                allow_redirects=True,
                ssl=False,
            ) as response:
                status = response.status

                # Definitive: 404 always means not found
                if status == 404:
                    return {"platform": platform, "url": full_url, "found": False, "status": status}

                # Non-200 and non-3xx → not found
                if status >= 400:
                    return {"platform": platform, "url": full_url, "found": False, "status": status}

                # Content-based validation for 200 responses
                if status == 200 and not config.get("no_content_check"):
                    body = await response.text(errors="ignore")
                    body_lower = body[:10000].lower()  # Only check first 10KB

                    # Check error patterns
                    for pattern in config.get("error_patterns", []):
                        if pattern.lower() in body_lower:
                            return {"platform": platform, "url": full_url, "found": False, "status": status, "reason": "error_pattern"}

                    # Check if redirected to homepage/login
                    final_url = str(response.url)
                    if username.lower() not in final_url.lower() and platform not in ("HackerNews",):
                        return {"platform": platform, "url": full_url, "found": False, "status": status, "reason": "redirect_away"}

                    # Try to extract profile data
                    profile_data = self._extract_profile_data(body, platform, config)

                    return {
                        "platform": platform,
                        "url": full_url,
                        "found": True,
                        "status": status,
                        "profile": profile_data,
                    }

                # 200 with no_content_check
                if status == 200:
                    return {"platform": platform, "url": full_url, "found": True, "status": status}

                # 3xx that landed somewhere
                return {"platform": platform, "url": full_url, "found": False, "status": status}

        except Exception:
            return {"platform": platform, "url": config["url"].format(username), "found": False, "status": 0}

    def _extract_profile_data(self, body: str, platform: str, config: dict) -> dict:
        """Extract basic profile data from the page when available."""
        data = {}
        body_lower = body[:20000]

        # Try to extract bio/description from Open Graph / meta tags
        og_desc = re.search(r'<meta\s+(?:property|name)=["\']og:description["\']\s+content=["\'](.*?)["\']', body_lower, re.I)
        if og_desc:
            data["bio"] = og_desc.group(1).strip()[:200]

        # Try to extract title
        og_title = re.search(r'<meta\s+(?:property|name)=["\']og:title["\']\s+content=["\'](.*?)["\']', body_lower, re.I)
        if og_title:
            data["display_name"] = og_title.group(1).strip()[:100]

        # Try to extract avatar/image
        og_image = re.search(r'<meta\s+(?:property|name)=["\']og:image["\']\s+content=["\'](.*?)["\']', body_lower, re.I)
        if og_image:
            data["avatar_url"] = og_image.group(1).strip()

        # Custom per-platform extraction
        if config.get("extract"):
            for key, pattern in config["extract"].items():
                match = re.search(pattern, body_lower, re.I)
                if match:
                    data[key] = match.group(1).strip()[:200]

        return data

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        options = options or {}
        max_concurrent = options.get("max_concurrent", 20)
        username = target.strip().lower()

        found_profiles = []
        all_results = []

        connector = aiohttp.TCPConnector(limit=max_concurrent, ssl=False)
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

        async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
            semaphore = asyncio.Semaphore(max_concurrent)

            async def limited_check(platform, config):
                async with semaphore:
                    return await self._check_platform(session, platform, config, username)

            tasks = [limited_check(p, c) for p, c in PLATFORMS.items()]
            all_results = await asyncio.gather(*tasks)

        for result in all_results:
            if result["found"]:
                found_profiles.append(result)

        # Build entities
        entities = []
        for profile in found_profiles:
            metadata = {
                "platform": profile["platform"],
                "username": username,
            }
            # Include profile data if extracted
            if profile.get("profile"):
                metadata.update(profile["profile"])

            confidence = 0.85 if profile.get("profile") else 0.7
            entities.append(EntityFound(
                entity_type="social_profile",
                value=profile["url"],
                source=self.name,
                confidence=confidence,
                metadata=metadata,
                relationships=[{"type": "HAS_PROFILE", "target": username}],
            ))

        return ScanResult(
            module=self.name,
            target=username,
            success=True,
            entities=entities,
            raw_data={
                "total_checked": len(PLATFORMS),
                "found": len(found_profiles),
                "profiles": found_profiles,
                "platforms_checked": list(PLATFORMS.keys()),
            },
            summary=f"Found {len(found_profiles)} profiles for '{username}' across {len(PLATFORMS)} platforms (content-validated)",
            severity="medium" if len(found_profiles) > 10 else "low",
        )


# Auto-register
ModuleRegistry.register(UsernameLookup())
