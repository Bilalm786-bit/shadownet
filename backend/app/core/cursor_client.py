"""
ShadowNet — Cursor Cloud Agents API Client
Programmatically manage Cursor Cloud Agents via the v1 REST API.
Docs: https://cursor.com/docs/cloud-agent/api/endpoints
"""

import httpx
import structlog
from typing import Optional, Dict, Any, List, AsyncGenerator

logger = structlog.get_logger(__name__)


class CursorAgentClient:
    """Client for the Cursor Cloud Agents API v1."""

    def __init__(self):
        self._api_key: Optional[str] = None
        self._base_url: str = "https://api.cursor.com"
        self._available = False

    def configure(self, api_key: str, base_url: str = "https://api.cursor.com"):
        """Configure the client with API credentials."""
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._available = bool(api_key)
        if self._available:
            logger.info("Cursor Cloud Agents API configured", base=self._base_url)
        else:
            logger.warning("Cursor API key not set — agent features disabled")

    @property
    def available(self) -> bool:
        return self._available

    def _auth(self) -> httpx.BasicAuth:
        """Basic auth: key as username, empty password."""
        return httpx.BasicAuth(username=self._api_key or "", password="")

    def _url(self, path: str) -> str:
        return f"{self._base_url}{path}"

    # ─── Agent CRUD ─────────────────────────────────────────

    async def create_agent(
        self,
        prompt_text: str,
        repo_url: str,
        starting_ref: str = "main",
        model_id: Optional[str] = None,
        auto_create_pr: bool = True,
        auto_generate_branch: bool = True,
        branch_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a Cloud Agent and immediately enqueue its initial run."""
        body: Dict[str, Any] = {
            "prompt": {"text": prompt_text},
            "repos": [{"url": repo_url, "startingRef": starting_ref}],
            "autoCreatePR": auto_create_pr,
            "autoGenerateBranch": auto_generate_branch,
        }
        if model_id:
            body["model"] = {"id": model_id}
        if branch_name:
            body["branchName"] = branch_name

        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                self._url("/v1/agents"),
                json=body,
                auth=self._auth(),
            )
            resp.raise_for_status()
            data = resp.json()
            logger.info("Agent created", agent_id=data.get("agent", {}).get("id"))
            return data

    async def list_agents(
        self, limit: int = 20, cursor: Optional[str] = None, include_archived: bool = True
    ) -> Dict[str, Any]:
        """List agents for the authenticated user, newest first."""
        params: Dict[str, Any] = {"limit": limit, "includeArchived": include_archived}
        if cursor:
            params["cursor"] = cursor

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                self._url("/v1/agents"),
                params=params,
                auth=self._auth(),
            )
            resp.raise_for_status()
            return resp.json()

    async def get_agent(self, agent_id: str) -> Dict[str, Any]:
        """Retrieve durable metadata for an agent."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                self._url(f"/v1/agents/{agent_id}"),
                auth=self._auth(),
            )
            resp.raise_for_status()
            return resp.json()

    async def archive_agent(self, agent_id: str) -> Dict[str, Any]:
        """Archive an agent (soft delete)."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                self._url(f"/v1/agents/{agent_id}/archive"),
                auth=self._auth(),
            )
            resp.raise_for_status()
            return resp.json()

    async def unarchive_agent(self, agent_id: str) -> Dict[str, Any]:
        """Unarchive an agent."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                self._url(f"/v1/agents/{agent_id}/unarchive"),
                auth=self._auth(),
            )
            resp.raise_for_status()
            return resp.json()

    async def delete_agent(self, agent_id: str) -> None:
        """Permanently delete an agent."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.delete(
                self._url(f"/v1/agents/{agent_id}"),
                auth=self._auth(),
            )
            resp.raise_for_status()

    # ─── Runs ───────────────────────────────────────────────

    async def create_run(
        self, agent_id: str, prompt_text: str
    ) -> Dict[str, Any]:
        """Send a follow-up prompt to an existing agent."""
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                self._url(f"/v1/agents/{agent_id}/runs"),
                json={"prompt": {"text": prompt_text}},
                auth=self._auth(),
            )
            resp.raise_for_status()
            return resp.json()

    async def list_runs(
        self, agent_id: str, limit: int = 20, cursor: Optional[str] = None
    ) -> Dict[str, Any]:
        """List runs for an agent, newest first."""
        params: Dict[str, Any] = {"limit": limit}
        if cursor:
            params["cursor"] = cursor

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                self._url(f"/v1/agents/{agent_id}/runs"),
                params=params,
                auth=self._auth(),
            )
            resp.raise_for_status()
            return resp.json()

    async def get_run(self, agent_id: str, run_id: str) -> Dict[str, Any]:
        """Retrieve status and timestamps for a specific run."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                self._url(f"/v1/agents/{agent_id}/runs/{run_id}"),
                auth=self._auth(),
            )
            resp.raise_for_status()
            return resp.json()

    async def cancel_run(self, agent_id: str, run_id: str) -> Dict[str, Any]:
        """Cancel the active run for an agent."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                self._url(f"/v1/agents/{agent_id}/runs/{run_id}/cancel"),
                auth=self._auth(),
            )
            resp.raise_for_status()
            return resp.json()

    async def stream_run(
        self, agent_id: str, run_id: str, last_event_id: Optional[str] = None
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Stream SSE events for a run. Yields parsed event dicts."""
        headers = {}
        if last_event_id:
            headers["Last-Event-ID"] = last_event_id

        async with httpx.AsyncClient(timeout=None) as client:
            async with client.stream(
                "GET",
                self._url(f"/v1/agents/{agent_id}/runs/{run_id}/stream"),
                auth=self._auth(),
                headers=headers,
            ) as response:
                response.raise_for_status()
                event_type = ""
                event_data = ""
                event_id = ""

                async for line in response.aiter_lines():
                    if line.startswith("event:"):
                        event_type = line[6:].strip()
                    elif line.startswith("data:"):
                        event_data = line[5:].strip()
                    elif line.startswith("id:"):
                        event_id = line[3:].strip()
                    elif line == "":
                        # End of event
                        if event_type and event_data:
                            import json
                            try:
                                parsed = json.loads(event_data)
                            except Exception:
                                parsed = {"raw": event_data}
                            yield {
                                "event": event_type,
                                "data": parsed,
                                "id": event_id,
                            }
                            if event_type in ("done", "error"):
                                return
                        event_type = ""
                        event_data = ""
                        event_id = ""

    # ─── Artifacts ──────────────────────────────────────────

    async def list_artifacts(self, agent_id: str) -> Dict[str, Any]:
        """List artifacts produced by an agent."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                self._url(f"/v1/agents/{agent_id}/artifacts"),
                auth=self._auth(),
            )
            resp.raise_for_status()
            return resp.json()

    async def download_artifact(self, agent_id: str, path: str) -> Dict[str, Any]:
        """Get a presigned download URL for an artifact."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                self._url(f"/v1/agents/{agent_id}/artifacts/download"),
                params={"path": path},
                auth=self._auth(),
            )
            resp.raise_for_status()
            return resp.json()

    # ─── Metadata ───────────────────────────────────────────

    async def get_me(self) -> Dict[str, Any]:
        """Retrieve API key info."""
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                self._url("/v1/me"),
                auth=self._auth(),
            )
            resp.raise_for_status()
            return resp.json()

    async def list_models(self) -> Dict[str, Any]:
        """List available models for cloud agents."""
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                self._url("/v1/models"),
                auth=self._auth(),
            )
            resp.raise_for_status()
            return resp.json()


# Singleton
cursor_client = CursorAgentClient()
