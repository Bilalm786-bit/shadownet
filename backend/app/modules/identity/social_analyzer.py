"""
ShadowNet — Deep Social Profile Analyzer
Extracts real profile data from discovered accounts — not just HTTP 200.
Pulls bios, avatar URLs, post counts, join dates, and cross-correlates usernames.
NO API key required.
"""

import aiohttp
import asyncio
import re
from typing import Dict, Any, List
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry
import structlog

logger = structlog.get_logger(__name__)

# Platform-specific profile data extraction
PROFILE_EXTRACTORS = {
    "github": {
        "api_url": "https://api.github.com/users/{}",
        "fields": {
            "name": "name", "bio": "bio", "avatar": "avatar_url",
            "followers": "followers", "following": "following",
            "public_repos": "public_repos", "location": "location",
            "company": "company", "blog": "blog", "created_at": "created_at",
            "twitter_username": "twitter_username",
        },
    },
    "gitlab": {
        "api_url": "https://gitlab.com/api/v4/users?username={}",
        "is_array": True,
        "fields": {
            "name": "name", "bio": "bio", "avatar": "avatar_url",
            "location": "location", "website": "website_url",
            "created_at": "created_at",
        },
    },
    "reddit": {
        "api_url": "https://www.reddit.com/user/{}/about.json",
        "data_key": "data",
        "fields": {
            "name": "name", "created_at": "created_utc",
            "comment_karma": "comment_karma", "link_karma": "link_karma",
            "avatar": "icon_img", "is_gold": "is_gold",
        },
    },
    "hackernews": {
        "api_url": "https://hacker-news.firebaseio.com/v0/user/{}.json",
        "fields": {
            "karma": "karma", "about": "about", "created_at": "created",
        },
    },
    "keybase": {
        "api_url": "https://keybase.io/_/api/1.0/user/lookup.json?usernames={}",
        "data_path": ["them", 0],
        "fields": {
            "name": "profile.full_name",
            "bio": "profile.bio",
            "location": "profile.location",
        },
    },
    "chess_com": {
        "api_url": "https://api.chess.com/pub/player/{}",
        "fields": {
            "name": "name", "avatar": "avatar", "url": "url",
            "followers": "followers", "joined": "joined",
            "country": "country", "status": "status",
        },
    },
    "lichess": {
        "api_url": "https://lichess.org/api/user/{}",
        "fields": {
            "name": "username", "bio": "profile.bio",
            "location": "profile.location", "created_at": "createdAt",
        },
    },
    "npm": {
        "api_url": "https://registry.npmjs.org/-/user/org.couchdb.user:{}",
        "fields": {
            "name": "name", "email": "email",
        },
    },
    "pypi": {
        "url": "https://pypi.org/user/{}/",
        "scrape": True,
    },
    "docker_hub": {
        "api_url": "https://hub.docker.com/v2/users/{}",
        "fields": {
            "name": "full_name", "bio": "company",
            "location": "location", "joined": "date_joined",
        },
    },
}


class SocialAnalyzer(OSINTModule):
    name = "identity.social_analyzer"
    description = "Deep social profile analysis — extracts real profile data and cross-correlates accounts (free, no key)"
    supported_target_types = ["username", "person"]
    requires_api_key = False
    rate_limit = 15

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        username = target.strip().lower()
        entities = []
        profiles = []
        errors = []

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json",
        }
        connector = aiohttp.TCPConnector(limit=10, ssl=False)

        async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
            tasks = {}
            for platform, config in PROFILE_EXTRACTORS.items():
                tasks[platform] = self._check_platform(session, platform, config, username)

            keys = list(tasks.keys())
            results = await asyncio.gather(*tasks.values(), return_exceptions=True)

            for platform, result in zip(keys, results):
                if isinstance(result, Exception):
                    errors.append(f"{platform}: {str(result)}")
                elif result and result.get("found"):
                    profiles.append(result)

        # Cross-correlate: look for linked accounts
        all_names = set()
        all_emails = set()
        all_locations = set()
        all_linked_accounts = {}

        for profile in profiles:
            data = profile.get("data", {})
            if data.get("name"):
                all_names.add(data["name"])
            if data.get("email"):
                all_emails.add(data["email"])
            if data.get("location"):
                all_locations.add(data["location"])
            if data.get("twitter_username"):
                all_linked_accounts["twitter"] = data["twitter_username"]
            if data.get("blog"):
                all_linked_accounts["blog"] = data["blog"]

        # Build entities
        for profile in profiles:
            platform = profile["platform"]
            data = profile.get("data", {})
            entities.append(EntityFound(
                entity_type="social_profile",
                value=profile.get("url", f"{platform}:{username}"),
                source=self.name,
                confidence=0.95,
                metadata={
                    "platform": platform,
                    "username": username,
                    **{k: v for k, v in data.items() if v and k != "avatar"},
                },
                relationships=[{"type": "HAS_PROFILE", "target": username}],
            ))

        # Add correlation entities
        for name in all_names:
            entities.append(EntityFound(
                entity_type="person", value=name, source=self.name, confidence=0.8,
                metadata={"username": username, "source_platforms": [p["platform"] for p in profiles if p.get("data", {}).get("name") == name]},
                relationships=[{"type": "REAL_NAME_OF", "target": username}],
            ))

        for email in all_emails:
            entities.append(EntityFound(
                entity_type="email", value=email, source=self.name, confidence=0.85,
                metadata={"username": username},
                relationships=[{"type": "USES_EMAIL", "target": username}],
            ))

        summary_parts = [
            f"Social analysis for '{username}'",
            f"Profiles found: {len(profiles)}/{len(PROFILE_EXTRACTORS)}",
        ]
        if all_names:
            summary_parts.append(f"Names: {', '.join(all_names)}")
        if all_emails:
            summary_parts.append(f"Emails: {', '.join(all_emails)}")
        if all_locations:
            summary_parts.append(f"Locations: {', '.join(all_locations)}")

        return ScanResult(
            module=self.name, target=username, success=True,
            entities=entities,
            raw_data={
                "profiles": profiles,
                "profile_count": len(profiles),
                "names_found": list(all_names),
                "emails_found": list(all_emails),
                "locations_found": list(all_locations),
                "linked_accounts": all_linked_accounts,
                "errors": errors,
            },
            summary=" | ".join(summary_parts),
            severity="medium" if len(profiles) > 3 else "low",
        )

    async def _check_platform(
        self, session: aiohttp.ClientSession, platform: str, config: dict, username: str
    ) -> dict:
        """Check a single platform API for profile data."""
        try:
            if config.get("scrape"):
                return await self._scrape_profile(session, platform, config, username)

            url = config["api_url"].format(username)
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 404:
                    return {"platform": platform, "found": False}
                if resp.status != 200:
                    return {"platform": platform, "found": False}

                data = await resp.json()

                # Handle array responses
                if config.get("is_array"):
                    if isinstance(data, list) and data:
                        data = data[0]
                    else:
                        return {"platform": platform, "found": False}

                # Handle nested data key
                if config.get("data_key"):
                    data = data.get(config["data_key"], data)

                # Handle nested data path
                if config.get("data_path"):
                    for key in config["data_path"]:
                        if isinstance(data, dict):
                            data = data.get(key, {})
                        elif isinstance(data, list) and isinstance(key, int):
                            data = data[key] if len(data) > key else {}

                if not data:
                    return {"platform": platform, "found": False}

                # Extract fields
                profile_data = {}
                for output_key, source_key in config.get("fields", {}).items():
                    if "." in source_key:
                        parts = source_key.split(".")
                        val = data
                        for p in parts:
                            val = val.get(p, {}) if isinstance(val, dict) else None
                            if val is None:
                                break
                    else:
                        val = data.get(source_key)
                    if val:
                        profile_data[output_key] = val

                if profile_data:
                    return {
                        "platform": platform,
                        "found": True,
                        "url": config["api_url"].format(username).replace("/api/", "/").replace("api.", ""),
                        "data": profile_data,
                    }

                return {"platform": platform, "found": False}

        except Exception as e:
            logger.debug(f"Social check failed for {platform}", error=str(e))
            return {"platform": platform, "found": False, "error": str(e)}

    async def _scrape_profile(
        self, session: aiohttp.ClientSession, platform: str, config: dict, username: str
    ) -> dict:
        """Scrape a profile page for data."""
        url = config["url"].format(username)
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status != 200:
                    return {"platform": platform, "found": False}
                body = await resp.text(errors="ignore")
                # Check for not-found indicators
                if "not found" in body.lower() or "404" in body[:1000]:
                    return {"platform": platform, "found": False}
                # Extract basic OG data
                profile_data = {}
                og_name = re.search(r'<meta\s+property=["\']og:title["\']\s+content=["\'](.*?)["\']', body, re.I)
                if og_name:
                    profile_data["name"] = og_name.group(1)
                og_desc = re.search(r'<meta\s+property=["\']og:description["\']\s+content=["\'](.*?)["\']', body, re.I)
                if og_desc:
                    profile_data["bio"] = og_desc.group(1)
                if profile_data:
                    return {"platform": platform, "found": True, "url": url, "data": profile_data}
                return {"platform": platform, "found": False}
        except Exception:
            return {"platform": platform, "found": False}


ModuleRegistry.register(SocialAnalyzer())
