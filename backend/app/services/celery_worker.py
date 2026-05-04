"""
ShadowNet — Celery Worker Configuration
Async task queue for background OSINT scans.
"""

from celery import Celery
from app.core.config import settings

celery_app = Celery(
    "shadownet",
    broker=settings.redis_url,
    backend=settings.redis_url,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=600,       # 10 minute max per task
    task_soft_time_limit=540,  # soft limit at 9 minutes
    worker_prefetch_multiplier=1,
    worker_concurrency=4,
)


@celery_app.task(name="shadownet.scan_target")
def scan_target_task(scan_id: str, target_id: str, module_name: str, options: dict = None):
    """
    Celery task wrapper for OSINT scans.
    In production, this dispatches to the ScanEngine.
    For development, scans run in-process via asyncio.create_task in the API.
    """
    import asyncio
    from app.services.scan_engine import scan_engine
    from app.core.database import async_session
    from sqlalchemy import select
    from app.models.models import Target

    async def _run():
        async with async_session() as db:
            result = await db.execute(select(Target).where(Target.id == target_id))
            target = result.scalar_one_or_none()
            if target:
                await scan_engine.execute_scan(
                    scan_id=scan_id,
                    target=target,
                    module_name=module_name,
                    options=options or {},
                    db=db,
                )
                await db.commit()

    asyncio.run(_run())
    return {"scan_id": scan_id, "status": "dispatched"}
