"""
ShadowNet — Reports API Routes
Generate PDF/HTML investigation reports.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.security import get_current_user
from app.models.models import Case, Target, ScanResult
from app.services.ai_analyst import ai_analyst
from typing import List
from datetime import datetime, timezone

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.post("/generate/{case_id}")
async def generate_report(
    case_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate an investigation report for a case."""
    # Get case
    result = await db.execute(
        select(Case).where(Case.id == case_id, Case.owner_id == current_user["sub"])
    )
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    # Get all targets and scan results
    targets_result = await db.execute(
        select(Target).where(Target.case_id == case_id)
    )
    targets = targets_result.scalars().all()

    all_findings = []
    for target in targets:
        scans_result = await db.execute(
            select(ScanResult).where(ScanResult.target_id == target.id)
        )
        scans = scans_result.scalars().all()
        for scan in scans:
            all_findings.append({
                "target": target.value,
                "target_type": target.target_type,
                "module": scan.module,
                "status": scan.status.value if hasattr(scan.status, 'value') else scan.status,
                "severity": scan.severity.value if hasattr(scan.severity, 'value') else scan.severity,
                "summary": scan.summary,
                "data": scan.data,
            })

    # Generate AI summary
    ai_summary = await ai_analyst.generate_report_summary(case.name, all_findings)

    report = {
        "case_id": case.id,
        "case_name": case.name,
        "description": case.description,
        "status": case.status.value if hasattr(case.status, 'value') else case.status,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_by": current_user.get("username", "unknown"),
        "target_count": len(targets),
        "finding_count": len(all_findings),
        "ai_summary": ai_summary,
        "targets": [
            {"value": t.value, "type": t.target_type, "label": t.label}
            for t in targets
        ],
        "findings": all_findings,
    }
    return report
