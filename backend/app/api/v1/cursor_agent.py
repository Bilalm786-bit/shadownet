"""
ShadowNet — Cursor Cloud Agents API Router
Manage Cursor Cloud Agents from the ShadowNet dashboard.
"""

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional, List
import json
import structlog

from app.core.cursor_client import cursor_client

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/cursor-agent", tags=["Cursor Cloud Agent"])


# ─── Request Models ─────────────────────────────────────

class CreateAgentRequest(BaseModel):
    prompt: str
    repo_url: str
    starting_ref: str = "main"
    model_id: Optional[str] = None
    auto_create_pr: bool = True
    auto_generate_branch: bool = True
    branch_name: Optional[str] = None

class CreateRunRequest(BaseModel):
    prompt: str


# ─── Helpers ────────────────────────────────────────────

def _check_available():
    if not cursor_client.available:
        raise HTTPException(
            status_code=503,
            detail="Cursor Cloud Agents API not configured. Set CURSOR_API_KEY in .env",
        )


# ─── Agent Endpoints ───────────────────────────────────

@router.post("/create")
async def create_agent(req: CreateAgentRequest):
    """Create a new Cloud Agent and launch its initial task."""
    _check_available()
    try:
        result = await cursor_client.create_agent(
            prompt_text=req.prompt,
            repo_url=req.repo_url,
            starting_ref=req.starting_ref,
            model_id=req.model_id,
            auto_create_pr=req.auto_create_pr,
            auto_generate_branch=req.auto_generate_branch,
            branch_name=req.branch_name,
        )
        return result
    except Exception as e:
        logger.error("Create agent failed", error=str(e))
        raise HTTPException(status_code=502, detail=f"Cursor API error: {str(e)}")


@router.get("/agents")
async def list_agents(limit: int = 20, cursor: Optional[str] = None):
    """List all Cloud Agents."""
    _check_available()
    try:
        return await cursor_client.list_agents(limit=limit, cursor=cursor)
    except Exception as e:
        logger.error("List agents failed", error=str(e))
        raise HTTPException(status_code=502, detail=str(e))


@router.get("/agents/{agent_id}")
async def get_agent(agent_id: str):
    """Get details for a specific agent."""
    _check_available()
    try:
        return await cursor_client.get_agent(agent_id)
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.post("/agents/{agent_id}/archive")
async def archive_agent(agent_id: str):
    """Archive an agent (soft delete)."""
    _check_available()
    try:
        return await cursor_client.archive_agent(agent_id)
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.post("/agents/{agent_id}/unarchive")
async def unarchive_agent(agent_id: str):
    """Unarchive an agent."""
    _check_available()
    try:
        return await cursor_client.unarchive_agent(agent_id)
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.delete("/agents/{agent_id}")
async def delete_agent(agent_id: str):
    """Permanently delete an agent."""
    _check_available()
    try:
        await cursor_client.delete_agent(agent_id)
        return {"status": "deleted", "agent_id": agent_id}
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


# ─── Run Endpoints ──────────────────────────────────────

@router.post("/agents/{agent_id}/run")
async def create_run(agent_id: str, req: CreateRunRequest):
    """Send a follow-up prompt to an existing agent."""
    _check_available()
    try:
        return await cursor_client.create_run(agent_id, req.prompt)
    except Exception as e:
        logger.error("Create run failed", error=str(e))
        raise HTTPException(status_code=502, detail=str(e))


@router.get("/agents/{agent_id}/runs")
async def list_runs(agent_id: str, limit: int = 20):
    """List runs for an agent."""
    _check_available()
    try:
        return await cursor_client.list_runs(agent_id, limit=limit)
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.get("/agents/{agent_id}/runs/{run_id}")
async def get_run(agent_id: str, run_id: str):
    """Get status for a specific run."""
    _check_available()
    try:
        return await cursor_client.get_run(agent_id, run_id)
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.post("/agents/{agent_id}/cancel/{run_id}")
async def cancel_run(agent_id: str, run_id: str):
    """Cancel an active run."""
    _check_available()
    try:
        return await cursor_client.cancel_run(agent_id, run_id)
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.get("/agents/{agent_id}/stream/{run_id}")
async def stream_run(agent_id: str, run_id: str):
    """Stream SSE events for a run in real-time."""
    _check_available()

    async def event_generator():
        try:
            async for event in cursor_client.stream_run(agent_id, run_id):
                yield f"event: {event['event']}\ndata: {json.dumps(event['data'])}\n"
                if event.get("id"):
                    yield f"id: {event['id']}\n"
                yield "\n"
        except Exception as e:
            yield f"event: error\ndata: {json.dumps({'message': str(e)})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ─── Artifact Endpoints ────────────────────────────────

@router.get("/artifacts/{agent_id}")
async def list_artifacts(agent_id: str):
    """List artifacts produced by an agent."""
    _check_available()
    try:
        return await cursor_client.list_artifacts(agent_id)
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.get("/artifacts/{agent_id}/download")
async def download_artifact(agent_id: str, path: str):
    """Get a presigned download URL for an artifact."""
    _check_available()
    try:
        return await cursor_client.download_artifact(agent_id, path)
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


# ─── Metadata Endpoints ────────────────────────────────

@router.get("/models")
async def list_models():
    """List available models for cloud agents."""
    _check_available()
    try:
        return await cursor_client.list_models()
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.get("/me")
async def get_api_key_info():
    """Get info about the Cursor API key."""
    _check_available()
    try:
        return await cursor_client.get_me()
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))
