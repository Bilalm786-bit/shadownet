"""
ShadowNet — Dashboard API Routes
Aggregate statistics for the main dashboard.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.core.database import get_db
from app.core.security import get_current_user
from app.models.models import Case, Target, ScanResult, Alert, ScanStatus, CaseStatus

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/stats")
async def get_dashboard_stats(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get aggregate statistics for the dashboard."""
    user_id = current_user["sub"]

    # Case counts
    total_cases = await db.execute(
        select(func.count(Case.id)).where(Case.owner_id == user_id)
    )
    active_cases = await db.execute(
        select(func.count(Case.id)).where(
            Case.owner_id == user_id, Case.status == CaseStatus.active
        )
    )

    # Target count
    total_targets = await db.execute(
        select(func.count(Target.id))
        .join(Case)
        .where(Case.owner_id == user_id)
    )

    # Scan counts
    total_scans = await db.execute(
        select(func.count(ScanResult.id))
        .join(Target)
        .join(Case)
        .where(Case.owner_id == user_id)
    )
    completed_scans = await db.execute(
        select(func.count(ScanResult.id))
        .join(Target)
        .join(Case)
        .where(Case.owner_id == user_id, ScanResult.status == ScanStatus.completed)
    )
    running_scans = await db.execute(
        select(func.count(ScanResult.id))
        .join(Target)
        .join(Case)
        .where(Case.owner_id == user_id, ScanResult.status == ScanStatus.running)
    )

    # Alert counts
    unread_alerts = await db.execute(
        select(func.count(Alert.id)).where(Alert.is_read == False)
    )

    # Recent scans
    recent_scans_result = await db.execute(
        select(ScanResult)
        .join(Target)
        .join(Case)
        .where(Case.owner_id == user_id)
        .order_by(ScanResult.created_at.desc())
        .limit(10)
    )
    recent_scans = []
    for s in recent_scans_result.scalars().all():
        try:
            recent_scans.append({
                "id": s.id,
                "module": s.module,
                "status": s.status.value if hasattr(s.status, 'value') else str(s.status),
                "severity": s.severity.value if hasattr(s.severity, 'value') else str(s.severity or "info"),
                "summary": s.summary,
                "created_at": s.created_at.isoformat() if s.created_at else None,
            })
        except Exception:
            pass

    # Recent alerts
    recent_alerts_result = await db.execute(
        select(Alert).order_by(Alert.created_at.desc()).limit(5)
    )
    recent_alerts = []
    for a in recent_alerts_result.scalars().all():
        try:
            recent_alerts.append({
                "id": a.id,
                "title": a.title,
                "severity": a.severity.value if hasattr(a.severity, 'value') else str(a.severity or "info"),
                "is_read": a.is_read,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            })
        except Exception:
            pass

    return {
        "cases": {
            "total": total_cases.scalar() or 0,
            "active": active_cases.scalar() or 0,
        },
        "targets": total_targets.scalar() or 0,
        "scans": {
            "total": total_scans.scalar() or 0,
            "completed": completed_scans.scalar() or 0,
            "running": running_scans.scalar() or 0,
        },
        "alerts": {
            "unread": unread_alerts.scalar() or 0,
        },
        "recent_scans": recent_scans,
        "recent_alerts": recent_alerts,
    }
