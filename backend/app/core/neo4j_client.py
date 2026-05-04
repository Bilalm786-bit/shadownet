"""
ShadowNet — Neo4j Graph Database Client
Gracefully degrades if neo4j package is not installed.
"""

from typing import Optional, List, Dict, Any
import structlog

logger = structlog.get_logger(__name__)

try:
    from neo4j import AsyncGraphDatabase
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False
    logger.warning("neo4j package not installed — graph features disabled")


class Neo4jClient:
    _driver = None
    _available = False

    @classmethod
    async def connect(cls):
        if not HAS_NEO4J:
            logger.info("Neo4j skipped (package not installed)")
            return
        from app.core.config import settings
        try:
            cls._driver = AsyncGraphDatabase.driver(
                settings.neo4j_uri,
                auth=(settings.neo4j_user, settings.neo4j_password),
            )
            cls._available = True
            logger.info("Neo4j connected", uri=settings.neo4j_uri)
        except Exception as e:
            logger.warning("Neo4j connection failed", error=str(e))

    @classmethod
    async def close(cls):
        if cls._driver:
            await cls._driver.close()

    @classmethod
    async def execute(cls, query: str, parameters: dict = None) -> List[Dict[str, Any]]:
        if not cls._available:
            return []
        async with cls._driver.session() as session:
            result = await session.run(query, parameters or {})
            return [record.data() async for record in result]

    @classmethod
    async def create_entity(cls, label: str, properties: dict) -> dict:
        if not cls._available:
            return {}
        query = f"""
        CREATE (n:{label} $props)
        SET n.created_at = datetime()
        RETURN n, elementId(n) as id
        """
        results = await cls.execute(query, {"props": properties})
        return results[0] if results else {}

    @classmethod
    async def create_relationship(cls, from_id: str, to_id: str, rel_type: str, properties: dict = None) -> dict:
        if not cls._available:
            return {}
        query = f"""
        MATCH (a) WHERE elementId(a) = $from_id
        MATCH (b) WHERE elementId(b) = $to_id
        CREATE (a)-[r:{rel_type} $props]->(b)
        SET r.created_at = datetime()
        RETURN type(r) as relationship, elementId(r) as id
        """
        results = await cls.execute(query, {"from_id": from_id, "to_id": to_id, "props": properties or {}})
        return results[0] if results else {}

    @classmethod
    async def get_entity_graph(cls, entity_id: str, depth: int = 2) -> list:
        if not cls._available:
            return []
        query = """
        MATCH path = (n)-[*1..$depth]-(m)
        WHERE elementId(n) = $entity_id
        RETURN nodes(path) as nodes, relationships(path) as rels
        LIMIT 500
        """
        return await cls.execute(query, {"entity_id": entity_id, "depth": depth})

    @classmethod
    async def search_entities(cls, label: str, search_term: str) -> List[dict]:
        if not cls._available:
            return []
        query = f"""
        MATCH (n:{label})
        WHERE any(key IN keys(n) WHERE toString(n[key]) CONTAINS $term)
        RETURN n, elementId(n) as id
        LIMIT 50
        """
        return await cls.execute(query, {"term": search_term})

    @classmethod
    async def get_case_graph(cls, case_id: str) -> list:
        if not cls._available:
            return []
        query = """
        MATCH (c:Case {case_id: $case_id})-[*1..3]-(n)
        WITH collect(DISTINCT n) as nodes
        UNWIND nodes as node
        OPTIONAL MATCH (node)-[r]-(other)
        WHERE other IN nodes
        RETURN collect(DISTINCT node) as nodes, collect(DISTINCT r) as relationships
        """
        return await cls.execute(query, {"case_id": case_id})
