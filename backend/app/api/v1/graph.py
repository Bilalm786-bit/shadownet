"""
ShadowNet — Graph API Routes
Entity relationship visualization powered by Neo4j.
"""

from fastapi import APIRouter, Depends
from app.core.security import get_current_user
from app.core.neo4j_client import Neo4jClient

router = APIRouter(prefix="/graph", tags=["Graph"])


@router.get("/case/{case_id}")
async def get_case_graph(
    case_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Get the full entity relationship graph for an investigation case."""
    try:
        data = await Neo4jClient.get_case_graph(case_id)
        nodes, edges, seen = [], [], set()
        for record in data:
            for node in record.get("nodes", []):
                nid = str(id(node))
                if nid not in seen:
                    seen.add(nid)
                    props = dict(node) if hasattr(node, '__iter__') else {}
                    nodes.append({
                        "id": nid,
                        "label": props.get("value", "Unknown"),
                        "entity_type": list(node.labels)[0] if hasattr(node, 'labels') else "Entity",
                        "properties": props,
                    })
            for rel in record.get("relationships", []):
                if rel:
                    edges.append({
                        "id": str(id(rel)),
                        "source": str(id(rel.start_node)) if hasattr(rel, 'start_node') else "",
                        "target": str(id(rel.end_node)) if hasattr(rel, 'end_node') else "",
                        "relationship": rel.type if hasattr(rel, 'type') else "RELATED",
                    })
        return {"nodes": nodes, "edges": edges}
    except Exception as e:
        return {"nodes": [], "edges": [], "error": str(e)}


@router.get("/entity/{entity_id}")
async def get_entity_graph(
    entity_id: str, depth: int = 2,
    current_user: dict = Depends(get_current_user),
):
    """Get an entity and its relationships up to N levels deep."""
    try:
        return {"data": await Neo4jClient.get_entity_graph(entity_id, depth)}
    except Exception as e:
        return {"data": [], "error": str(e)}
