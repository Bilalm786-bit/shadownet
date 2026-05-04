"""
ShadowNet — Targets API Routes
Manage investigation targets within cases.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List
from app.core.database import get_db
from app.core.security import get_current_user
from app.core.neo4j_client import Neo4jClient
from app.models.models import Target, Case
from app.schemas.schemas import TargetCreate, TargetResponse

router = APIRouter(prefix="/cases/{case_id}/targets", tags=["Targets"])


@router.post("/", response_model=TargetResponse, status_code=201)
async def add_target(
    case_id: str,
    payload: TargetCreate,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Add a new target to an investigation case."""
    # Verify case ownership
    result = await db.execute(
        select(Case).where(Case.id == case_id, Case.owner_id == current_user["sub"])
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Case not found")

    # Create Neo4j entity node (optional)
    neo4j_node_id = ""
    try:
        label_map = {
            "email": "Email", "username": "Username", "domain": "Domain",
            "ip": "IP", "phone": "Phone", "person": "Person",
            "organization": "Organization", "url": "URL",
        }
        neo4j_label = label_map.get(payload.target_type.value, "Entity")
        neo4j_result = await Neo4jClient.create_entity(
            neo4j_label,
            {"value": payload.value, "case_id": case_id, **payload.extra_data},
        )
        neo4j_node_id = neo4j_result.get("id", "")
    except Exception:
        pass

    target = Target(
        case_id=case_id,
        target_type=payload.target_type.value,
        value=payload.value,
        label=payload.label or payload.value,
        extra_data=payload.extra_data,
        neo4j_node_id=neo4j_node_id,
    )
    db.add(target)
    await db.flush()
    await db.refresh(target)
    await db.commit()
    return target


@router.get("/", response_model=List[TargetResponse])
async def list_targets(
    case_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all targets in a case."""
    result = await db.execute(
        select(Target).where(Target.case_id == case_id).order_by(Target.created_at.desc())
    )
    return result.scalars().all()


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(
    case_id: str,
    target_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a specific target."""
    result = await db.execute(
        select(Target).where(Target.id == target_id, Target.case_id == case_id)
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@router.delete("/{target_id}", status_code=204)
async def delete_target(
    case_id: str,
    target_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove a target from a case."""
    result = await db.execute(
        select(Target).where(Target.id == target_id, Target.case_id == case_id)
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    await db.delete(target)
