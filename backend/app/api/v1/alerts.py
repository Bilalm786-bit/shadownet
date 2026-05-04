"""
ShadowNet — Alerts API Routes
Alert management for threat notifications.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, update
from typing import List, Optional
from app.core.database import get_db
from app.core.security import get_current_user
from app.models.models import Alert
from app.schemas.schemas import AlertResponse

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("/", response_model=List[AlertResponse])
async def list_alerts(
    severity: Optional[str] = None,
    is_read: Optional[bool] = None,
    limit: int = 50,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List alerts with optional filters."""
    query = select(Alert).order_by(Alert.created_at.desc()).limit(limit)
    if severity:
        query = query.where(Alert.severity == severity)
    if is_read is not None:
        query = query.where(Alert.is_read == is_read)

    result = await db.execute(query)
    return result.scalars().all()


@router.get("/unread-count")
async def unread_count(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get count of unread alerts."""
    result = await db.execute(
        select(func.count(Alert.id)).where(Alert.is_read == False)
    )
    count = result.scalar() or 0
    return {"unread_count": count}


@router.patch("/{alert_id}/read", response_model=AlertResponse)
async def mark_as_read(
    alert_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Mark an alert as read."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.is_read = True
    await db.flush()
    await db.refresh(alert)
    return alert


@router.patch("/read-all")
async def mark_all_read(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Mark all alerts as read."""
    await db.execute(update(Alert).where(Alert.is_read == False).values(is_read=True))
    return {"message": "All alerts marked as read"}
