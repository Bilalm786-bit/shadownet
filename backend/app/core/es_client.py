"""
ShadowNet — Elasticsearch Client
Full-text search across all collected intelligence data.
Gracefully degrades if elasticsearch package is not installed.
"""

from typing import List, Dict, Any, Optional
import structlog

logger = structlog.get_logger(__name__)

INTEL_INDEX = "shadownet-intel"
SCANS_INDEX = "shadownet-scans"

try:
    from elasticsearch import AsyncElasticsearch
    HAS_ES = True
except ImportError:
    HAS_ES = False
    logger.warning("elasticsearch package not installed — search features disabled")


class ESClient:
    _client = None
    _available = False

    @classmethod
    async def connect(cls):
        if not HAS_ES:
            logger.info("Elasticsearch skipped (package not installed)")
            return
        from app.core.config import settings
        try:
            cls._client = AsyncElasticsearch(settings.elasticsearch_url)
            cls._available = True
            logger.info("Elasticsearch connected", url=settings.elasticsearch_url)
        except Exception as e:
            logger.warning("Elasticsearch connection failed", error=str(e))

    @classmethod
    async def close(cls):
        if cls._client:
            await cls._client.close()

    @classmethod
    async def index_document(cls, index: str, doc: dict, doc_id: str = None) -> dict:
        if not cls._available:
            return {}
        result = await cls._client.index(index=index, document=doc, id=doc_id)
        return result

    @classmethod
    async def search(cls, query: str, index: str = INTEL_INDEX, filters: dict = None, size: int = 50) -> List[Dict]:
        if not cls._available:
            return []
        must = [{"multi_match": {"query": query, "fields": ["content", "tags"]}}]
        if filters:
            for k, v in filters.items():
                must.append({"term": {k: v}})
        body = {"query": {"bool": {"must": must}}, "size": size, "sort": [{"timestamp": {"order": "desc"}}]}
        result = await cls._client.search(index=index, body=body)
        return [hit["_source"] for hit in result["hits"]["hits"]]

    @classmethod
    async def search_by_case(cls, case_id: str, query: str = None) -> List[dict]:
        if not cls._available:
            return []
        must = [{"term": {"case_id": case_id}}]
        if query:
            must.append({"multi_match": {"query": query, "fields": ["content"]}})
        body = {"query": {"bool": {"must": must}}, "size": 200}
        result = await cls._client.search(index=INTEL_INDEX, body=body)
        return [hit["_source"] for hit in result["hits"]["hits"]]
