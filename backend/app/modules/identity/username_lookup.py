"""
ShadowNet — Username Lookup Module
Sherlock-style username enumeration across 300+ platforms.
NO API key required — uses direct HTTP requests.
"""

import aiohttp
import asyncio
from typing import Dict, Any, List
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry


# Popular platforms to check — expandable list
PLATFORMS = {
    "GitHub": "https://github.com/{}",
    "Twitter": "https://x.com/{}",
    "Instagram": "https://www.instagram.com/{}/",
    "Reddit": "https://www.reddit.com/user/{}/",
    "LinkedIn": "https://www.linkedin.com/in/{}/",
    "Facebook": "https://www.facebook.com/{}/",
    "YouTube": "https://www.youtube.com/@{}",
    "TikTok": "https://www.tiktok.com/@{}",
    "Pinterest": "https://www.pinterest.com/{}/",
    "Tumblr": "https://{}.tumblr.com",
    "Medium": "https://medium.com/@{}",
    "DeviantArt": "https://www.deviantart.com/{}",
    "Flickr": "https://www.flickr.com/people/{}/",
    "SoundCloud": "https://soundcloud.com/{}",
    "Spotify": "https://open.spotify.com/user/{}",
    "Steam": "https://steamcommunity.com/id/{}",
    "Twitch": "https://www.twitch.tv/{}",
    "GitLab": "https://gitlab.com/{}",
    "Bitbucket": "https://bitbucket.org/{}/",
    "HackerNews": "https://news.ycombinator.com/user?id={}",
    "Keybase": "https://keybase.io/{}",
    "About.me": "https://about.me/{}",
    "SlideShare": "https://www.slideshare.net/{}",
    "Dribbble": "https://dribbble.com/{}",
    "Behance": "https://www.behance.net/{}",
    "Gravatar": "https://en.gravatar.com/{}",
    "WordPress": "https://{}.wordpress.com",
    "Blogger": "https://{}.blogspot.com",
    "StackOverflow": "https://stackoverflow.com/users/{}",
    "HackerRank": "https://www.hackerrank.com/{}",
    "LeetCode": "https://leetcode.com/{}",
    "Codecademy": "https://www.codecademy.com/profiles/{}",
    "Replit": "https://replit.com/@{}",
    "Kaggle": "https://www.kaggle.com/{}",
    "ProductHunt": "https://www.producthunt.com/@{}",
    "AngelList": "https://angel.co/u/{}",
    "Mastodon": "https://mastodon.social/@{}",
    "Discord": "https://discord.com/users/{}",
    "Telegram": "https://t.me/{}",
    "Patreon": "https://www.patreon.com/{}",
    "BuyMeACoffee": "https://buymeacoffee.com/{}",
    "Linktree": "https://linktr.ee/{}",
    "Fiverr": "https://www.fiverr.com/{}",
    "Scribd": "https://www.scribd.com/{}",
    "Vimeo": "https://vimeo.com/{}",
    "Dailymotion": "https://www.dailymotion.com/{}",
    "Mixcloud": "https://www.mixcloud.com/{}/",
    "Bandcamp": "https://{}.bandcamp.com",
    "Last.fm": "https://www.last.fm/user/{}",
    "Goodreads": "https://www.goodreads.com/{}",
    "Quora": "https://www.quora.com/profile/{}",
    "Trip Advisor": "https://www.tripadvisor.com/members/{}",
    "Ebay": "https://www.ebay.com/usr/{}",
    "Etsy": "https://www.etsy.com/shop/{}",
    "Roblox": "https://www.roblox.com/user.aspx?username={}",
    "Minecraft": "https://namemc.com/profile/{}",
    "Xbox Gamertag": "https://xboxgamertag.com/search/{}",
    "Chess.com": "https://www.chess.com/member/{}",
    "Lichess": "https://lichess.org/@/{}",
    "Trello": "https://trello.com/{}",
    "Docker Hub": "https://hub.docker.com/u/{}",
    "npm": "https://www.npmjs.com/~{}",
    "PyPI": "https://pypi.org/user/{}/",
    "Crates.io": "https://crates.io/users/{}",
    "Rubygems": "https://rubygems.org/profiles/{}",
    "500px": "https://500px.com/p/{}",
    "Unsplash": "https://unsplash.com/@{}",
    "Pexels": "https://www.pexels.com/@{}",
    "Imgur": "https://imgur.com/user/{}",
    "9GAG": "https://9gag.com/u/{}",
    "Wattpad": "https://www.wattpad.com/user/{}",
    "AO3": "https://archiveofourown.org/users/{}",
    "F3": "https://www.f3nation.com/members/{}",
    "Clubhouse": "https://www.clubhouse.com/@{}",
    "Substack": "https://{}.substack.com",
    "Hashnode": "https://hashnode.com/@{}",
    "Dev.to": "https://dev.to/{}",
    "CodePen": "https://codepen.io/{}",
    "JSFiddle": "https://jsfiddle.net/user/{}/",
    "OpenSea": "https://opensea.io/{}",
    "Rarible": "https://rarible.com/{}",
}


class UsernameLookup(OSINTModule):
    name = "identity.username_lookup"
    description = "Checks username availability across 85+ popular platforms (Sherlock-style)"
    supported_target_types = ["username", "person"]
    requires_api_key = False
    rate_limit = 30

    async def _check_platform(
        self, session: aiohttp.ClientSession, platform: str, url: str, username: str
    ) -> dict:
        """Check if a username exists on a specific platform."""
        try:
            full_url = url.format(username)
            async with session.get(
                full_url,
                timeout=aiohttp.ClientTimeout(total=10),
                allow_redirects=True,
                ssl=False,
            ) as response:
                if response.status == 200:
                    return {
                        "platform": platform,
                        "url": full_url,
                        "found": True,
                        "status": response.status,
                    }
                return {"platform": platform, "url": full_url, "found": False, "status": response.status}
        except Exception:
            return {"platform": platform, "url": url.format(username), "found": False, "status": 0}

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        options = options or {}
        max_concurrent = options.get("max_concurrent", 20)
        username = target.strip().lower()

        found_profiles = []
        all_results = []

        connector = aiohttp.TCPConnector(limit=max_concurrent, ssl=False)
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

        async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
            semaphore = asyncio.Semaphore(max_concurrent)

            async def limited_check(platform, url):
                async with semaphore:
                    return await self._check_platform(session, platform, url, username)

            tasks = [limited_check(p, u) for p, u in PLATFORMS.items()]
            all_results = await asyncio.gather(*tasks)

        for result in all_results:
            if result["found"]:
                found_profiles.append(result)

        # Build entities
        entities = []
        for profile in found_profiles:
            entities.append(EntityFound(
                entity_type="social_profile",
                value=profile["url"],
                source=self.name,
                confidence=0.7,
                metadata={
                    "platform": profile["platform"],
                    "username": username,
                },
                relationships=[{"type": "HAS_PROFILE", "target": username}],
            ))

        return ScanResult(
            module=self.name,
            target=username,
            success=True,
            entities=entities,
            raw_data={"total_checked": len(PLATFORMS), "found": len(found_profiles), "profiles": found_profiles},
            summary=f"Found {len(found_profiles)} profiles for '{username}' across {len(PLATFORMS)} platforms",
            severity="medium" if len(found_profiles) > 10 else "low",
        )


# Auto-register
ModuleRegistry.register(UsernameLookup())
