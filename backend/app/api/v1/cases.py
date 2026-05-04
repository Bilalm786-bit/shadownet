"""
ShadowNet — Cases API Routes
Investigation case management.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload
from typing import List
from app.core.database import get_db
from app.core.security import get_current_user
from app.models.models import Case, Target
from app.schemas.schemas import CaseCreate, CaseUpdate, CaseResponse

router = APIRouter(prefix="/cases", tags=["Cases"])


def _case_to_response(case: Case, target_count: int = 0) -> CaseResponse:
    """Convert a Case ORM object to CaseResponse, handling enum serialization."""
    return CaseResponse(
        id=case.id,
        name=case.name,
        description=case.description,
        status=case.status.value if hasattr(case.status, 'value') else str(case.status),
        priority=case.priority,
        tags=case.tags or [],
        owner_id=case.owner_id,
        created_at=case.created_at,
        updated_at=case.updated_at,
        target_count=target_count,
    )


@router.post("/", response_model=CaseResponse, status_code=201)
async def create_case(
    payload: CaseCreate,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new investigation case."""
    case = Case(
        name=payload.name,
        description=payload.description,
        priority=payload.priority,
        tags=payload.tags,
        owner_id=current_user["sub"],
    )
    db.add(case)
    await db.flush()
    await db.refresh(case)
    await db.commit()
    return _case_to_response(case, 0)


@router.get("/", response_model=List[CaseResponse])
async def list_cases(
    status: str = None,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all cases for the current user."""
    query = (
        select(Case, func.count(Target.id).label("target_count"))
        .outerjoin(Target)
        .where(Case.owner_id == current_user["sub"])
        .group_by(Case.id)
        .order_by(Case.created_at.desc())
    )
    if status:
        query = query.where(Case.status == status)

    result = await db.execute(query)
    cases = []
    for case, count in result.all():
        cases.append(_case_to_response(case, count))
    return cases


@router.get("/{case_id}", response_model=CaseResponse)
async def get_case(
    case_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a specific case by ID."""
    result = await db.execute(
        select(Case, func.count(Target.id))
        .outerjoin(Target)
        .where(Case.id == case_id, Case.owner_id == current_user["sub"])
        .group_by(Case.id)
    )
    row = result.first()
    if not row:
        raise HTTPException(status_code=404, detail="Case not found")
    case, count = row
    return _case_to_response(case, count)


@router.patch("/{case_id}", response_model=CaseResponse)
async def update_case(
    case_id: str,
    payload: CaseUpdate,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update a case."""
    result = await db.execute(
        select(Case).where(Case.id == case_id, Case.owner_id == current_user["sub"])
    )
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    update_data = payload.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(case, key, value)

    await db.flush()
    await db.refresh(case)
    return _case_to_response(case, 0)


@router.delete("/{case_id}", status_code=204)
async def delete_case(
    case_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a case and all its targets/results."""
    result = await db.execute(
        select(Case).where(Case.id == case_id, Case.owner_id == current_user["sub"])
    )
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    await db.delete(case)
