"""
ShadowNet — Search API Routes
Full-text intelligence search powered by Elasticsearch.
"""

from fastapi import APIRouter, Depends, Query
from app.core.security import get_current_user
from app.core.es_client import ESClient, INTEL_INDEX
from typing import Optional

router = APIRouter(prefix="/search", tags=["Search"])


@router.get("/")
async def search_intel(
    q: str = Query(..., min_length=1, description="Search query"),
    severity: Optional[str] = None,
    module: Optional[str] = None,
    limit: int = Query(50, le=200),
    current_user: dict = Depends(get_current_user),
):
    """Full-text search across all collected intelligence data."""
    filters = {}
    if severity:
        filters["severity"] = severity
    if module:
        filters["module"] = module

    try:
        results = await ESClient.search(q, index=INTEL_INDEX, filters=filters, size=limit)
        return {"query": q, "count": len(results), "results": results}
    except Exception as e:
        return {"query": q, "count": 0, "results": [], "error": str(e)}


@router.get("/case/{case_id}")
async def search_case_intel(
    case_id: str,
    q: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    """Search intelligence within a specific investigation case."""
    try:
        results = await ESClient.search_by_case(case_id, query=q)
        return {"case_id": case_id, "query": q, "count": len(results), "results": results}
    except Exception as e:
        return {"case_id": case_id, "count": 0, "results": [], "error": str(e)}
