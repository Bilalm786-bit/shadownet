"""
ShadowNet — GitHub Reconnaissance Module
Public GitHub API — repos, gists, commit history, email extraction.
NO API key needed (60 requests/hour unauthenticated).
"""

import aiohttp
from typing import Dict, Any, List
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry


class GitHubRecon(OSINTModule):
    name = "socmint.github_recon"
    description = "GitHub profile enumeration — repos, gists, commit emails, orgs (free, no key)"
    supported_target_types = ["username"]
    requires_api_key = False
    rate_limit = 60

    API_BASE = "https://api.github.com"

    async def _fetch(self, session: aiohttp.ClientSession, url: str) -> dict | list | None:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    return await resp.json()
        except Exception:
            pass
        return None

    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        username = target.strip()
        entities = []
        headers = {"Accept": "application/vnd.github.v3+json", "User-Agent": "ShadowNet-OSINT"}

        async with aiohttp.ClientSession(headers=headers) as session:
            # 1. User profile
            profile = await self._fetch(session, f"{self.API_BASE}/users/{username}")
            if not profile or profile.get("message") == "Not Found":
                return ScanResult(
                    module=self.name, target=username, success=True,
                    summary=f"GitHub user '{username}' not found",
                    raw_data={"found": False},
                )

            user_data = {
                "login": profile.get("login"),
                "name": profile.get("name"),
                "bio": profile.get("bio"),
                "company": profile.get("company"),
                "location": profile.get("location"),
                "email": profile.get("email"),
                "blog": profile.get("blog"),
                "twitter": profile.get("twitter_username"),
                "public_repos": profile.get("public_repos"),
                "public_gists": profile.get("public_gists"),
                "followers": profile.get("followers"),
                "following": profile.get("following"),
                "created_at": profile.get("created_at"),
                "avatar_url": profile.get("avatar_url"),
                "html_url": profile.get("html_url"),
                "hireable": profile.get("hireable"),
            }

            # Profile entity
            entities.append(EntityFound(
                entity_type="social_profile", value=profile.get("html_url", ""),
                source=self.name, confidence=1.0,
                metadata=user_data,
                relationships=[{"type": "HAS_GITHUB", "target": username}],
            ))

            # Extract real name
            if user_data.get("name"):
                entities.append(EntityFound(
                    entity_type="person", value=user_data["name"],
                    source=self.name, confidence=0.8,
                    metadata={"source": "github_profile"},
                    relationships=[{"type": "KNOWN_AS", "target": username}],
                ))

            # Extract email
            if user_data.get("email"):
                entities.append(EntityFound(
                    entity_type="email", value=user_data["email"],
                    source=self.name, confidence=0.9,
                    relationships=[{"type": "USES_EMAIL", "target": username}],
                ))

            # Extract company/org
            if user_data.get("company"):
                entities.append(EntityFound(
                    entity_type="organization", value=user_data["company"].lstrip("@"),
                    source=self.name, confidence=0.7,
                    relationships=[{"type": "WORKS_AT", "target": username}],
                ))

            # Extract location
            if user_data.get("location"):
                entities.append(EntityFound(
                    entity_type="location", value=user_data["location"],
                    source=self.name, confidence=0.6,
                    relationships=[{"type": "LOCATED_IN", "target": username}],
                ))

            # Extract blog/website
            if user_data.get("blog"):
                entities.append(EntityFound(
                    entity_type="url", value=user_data["blog"],
                    source=self.name, confidence=0.9,
                    relationships=[{"type": "OWNS_WEBSITE", "target": username}],
                ))

            # 2. Repos — look for commit emails
            repos = await self._fetch(session, f"{self.API_BASE}/users/{username}/repos?per_page=10&sort=updated")
            commit_emails = set()
            if repos:
                user_data["repos"] = [{"name": r["name"], "url": r["html_url"], "language": r.get("language"), "stars": r.get("stargazers_count")} for r in repos[:10]]
                for repo in repos[:5]:
                    commits = await self._fetch(session, f"{self.API_BASE}/repos/{username}/{repo['name']}/commits?per_page=5")
                    if commits:
                        for commit in commits:
                            c_data = commit.get("commit", {})
                            author = c_data.get("author", {})
                            if author.get("email") and "noreply" not in author["email"]:
                                commit_emails.add(author["email"])

            for email in commit_emails:
                entities.append(EntityFound(
                    entity_type="email", value=email,
                    source=self.name, confidence=0.85,
                    metadata={"source": "github_commits"},
                    relationships=[{"type": "COMMIT_EMAIL", "target": username}],
                ))

            # 3. Orgs
            orgs = await self._fetch(session, f"{self.API_BASE}/users/{username}/orgs")
            if orgs:
                user_data["organizations"] = [{"login": o["login"], "url": o.get("url")} for o in orgs]
                for org in orgs:
                    entities.append(EntityFound(
                        entity_type="organization", value=org["login"],
                        source=self.name, confidence=0.9,
                        relationships=[{"type": "MEMBER_OF", "target": username}],
                    ))

        summary = (
            f"GitHub: {username} | Name: {user_data.get('name', 'N/A')} | "
            f"Repos: {user_data.get('public_repos', 0)} | "
            f"Followers: {user_data.get('followers', 0)} | "
            f"Emails found: {len(commit_emails) + (1 if user_data.get('email') else 0)}"
        )

        return ScanResult(
            module=self.name, target=username, success=True,
            entities=entities, raw_data=user_data, summary=summary,
        )


ModuleRegistry.register(GitHubRecon())
