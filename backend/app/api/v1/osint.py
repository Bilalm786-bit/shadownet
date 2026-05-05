"""
ShadowNet — OSINT Scan API Routes
Launch scans, check status, get results.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List
from app.core.database import get_db
from app.core.security import get_current_user
from app.models.models import Target, ScanResult, ScanStatus
from app.schemas.schemas import ScanRequest, ScanResultResponse
from app.modules.base import ModuleRegistry

router = APIRouter(prefix="/osint", tags=["OSINT Scanning"])


@router.post("/scan", status_code=202)
async def launch_scan(
    payload: ScanRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Launch an OSINT scan against a target using specified modules."""
    # Verify target exists
    result = await db.execute(select(Target).where(Target.id == payload.target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # Determine which modules to run
    target_type_str = target.target_type.value if hasattr(target.target_type, 'value') else str(target.target_type)
    if "all" in payload.modules:
        modules = ModuleRegistry.get_modules_for_type(target_type_str)
    else:
        modules = payload.modules

    if not modules:
        raise HTTPException(status_code=400, detail=f"No modules available for target type '{target_type_str}'")

    # Create scan result entries
    scan_ids = []
    for module_name in modules:
        scan = ScanResult(
            target_id=target.id,
            module=module_name,
            status=ScanStatus.pending,
        )
        db.add(scan)
        await db.flush()
        await db.refresh(scan)
        scan_ids.append(scan.id)

    # Capture target data BEFORE the request ends
    # (the db session will close after this response, so we extract what we need)
    target_value = target.value
    target_type = target_type_str
    target_case_id = target.case_id
    target_neo4j_node_id = target.neo4j_node_id or ""
    target_id = target.id

    # Execute scans in background (async, in-process)
    import asyncio
    from app.services.scan_engine import scan_engine

    asyncio.create_task(
        scan_engine.run_all_modules(
            target_value=target_value,
            target_type=target_type,
            target_case_id=target_case_id,
            target_neo4j_node_id=target_neo4j_node_id,
            target_id=target_id,
            modules=modules,
            scan_ids=scan_ids,
            options=payload.options,
            user_id=current_user.get("sub"),
        )
    )

    return {
        "message": f"Scan launched with {len(modules)} modules",
        "scan_ids": scan_ids,
        "modules": modules,
        "target": target_value,
    }


@router.get("/results/{target_id}", response_model=List[ScanResultResponse])
async def get_scan_results(
    target_id: str,
    module: str = None,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get scan results for a target."""
    query = select(ScanResult).where(ScanResult.target_id == target_id)
    if module:
        query = query.where(ScanResult.module == module)
    query = query.order_by(ScanResult.created_at.desc())

    result = await db.execute(query)
    scans = result.scalars().all()

    # Manually serialize to handle enum conversion
    return [_scan_to_response(s) for s in scans]


@router.get("/status/{scan_id}", response_model=ScanResultResponse)
async def get_scan_status(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Check status of a specific scan."""
    result = await db.execute(select(ScanResult).where(ScanResult.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _scan_to_response(scan)


@router.get("/modules")
async def list_modules(current_user: dict = Depends(get_current_user)):
    """List all available OSINT modules and their supported target types."""
    return ModuleRegistry.list_all()


@router.post("/auto-investigate")
async def auto_investigate(
    payload: dict,
    current_user: dict = Depends(get_current_user),
):
    """
    One-click auto-investigation.
    Input: { "target": "any-string", "depth": 1-2 }
    Auto-detects target type and runs ALL relevant modules.
    """
    from app.services.auto_investigator import auto_investigator

    target = payload.get("target", "").strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target is required")

    depth = min(payload.get("depth", 1), 2)
    target_type = payload.get("target_type")  # Optional override

    # Run investigation (this may take a while)
    result = await auto_investigator.investigate(
        target=target,
        target_type=target_type,
        depth=depth,
    )

    return result


@router.post("/quick-scan")
async def quick_scan(
    payload: dict,
    current_user: dict = Depends(get_current_user),
):
    """
    Quick single-module scan without requiring a case.
    Input: { "target": "value", "module": "module.name" }
    """
    target = payload.get("target", "").strip()
    module_name = payload.get("module", "").strip()

    if not target or not module_name:
        raise HTTPException(status_code=400, detail="target and module are required")

    module = ModuleRegistry.get(module_name)
    if not module:
        raise HTTPException(status_code=404, detail=f"Module '{module_name}' not found")

    options = payload.get("options", {})
    result = await module.scan(target, options)

    return {
        "module": result.module,
        "target": result.target,
        "success": result.success,
        "summary": result.summary,
        "severity": result.severity,
        "entity_count": len(result.entities),
        "entities": [
            {
                "type": e.entity_type,
                "value": e.value,
                "confidence": e.confidence,
                "metadata": e.metadata,
            }
            for e in result.entities
        ],
        "raw_data": result.raw_data,
        "error": result.error,
    }


@router.get("/detect-type")
async def detect_target_type(
    target: str,
    current_user: dict = Depends(get_current_user),
):
    """Auto-detect the type of a target string."""
    from app.services.auto_investigator import AutoInvestigator
    detected = AutoInvestigator.detect_target_type(target)
    available_modules = ModuleRegistry.get_modules_for_type(detected)
    return {
        "target": target,
        "detected_type": detected,
        "available_modules": available_modules,
        "module_count": len(available_modules),
    }


def _scan_to_response(scan: ScanResult) -> dict:
    """Convert ORM ScanResult to dict, handling enum serialization."""
    return {
        "id": scan.id,
        "target_id": scan.target_id,
        "module": scan.module,
        "status": scan.status.value if hasattr(scan.status, 'value') else str(scan.status),
        "severity": scan.severity.value if hasattr(scan.severity, 'value') else str(scan.severity or "info"),
        "summary": scan.summary,
        "data": scan.data or {},
        "error_message": scan.error_message,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "created_at": scan.created_at,
    }
