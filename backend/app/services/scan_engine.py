"""
ShadowNet — Scan Execution Engine
Runs OSINT modules against targets and persists results.
"""

from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.models import ScanResult, ScanStatus, Target
from app.modules.base import ModuleRegistry, ScanResult as ModuleScanResult
from app.core.es_client import ESClient, INTEL_INDEX
from app.core.neo4j_client import Neo4jClient
from app.core.database import async_session  # OWN session factory
from app.api.v1.websocket import ws_manager
from app.services.ai_analyst import ai_analyst
from app.services.auto_investigator import AutoInvestigator
import structlog

logger = structlog.get_logger(__name__)


class ScanEngine:
    """Orchestrates OSINT scans across modules."""

    @staticmethod
    async def execute_scan(
        scan_id: str,
        target_value: str,
        target_type: str,
        target_case_id: str,
        target_neo4j_node_id: str,
        target_id: str,
        module_name: str,
        options: Dict[str, Any],
        user_id: str = None,
    ) -> Optional[ModuleScanResult]:
        """Execute a single OSINT module scan and persist results.
        
        NOTE: This method creates its OWN database session because it runs
        as a background task after the HTTP request has completed.
        The request-scoped session is already closed by the time this runs.
        """

        # Get the module
        module = ModuleRegistry.get(module_name)
        if not module:
            async with async_session() as db:
                await ScanEngine._update_scan_status(
                    db, scan_id, ScanStatus.failed,
                    error_message=f"Module '{module_name}' not found",
                )
                await db.commit()
            return None

        # Mark as running
        async with async_session() as db:
            await ScanEngine._update_scan_status(db, scan_id, ScanStatus.running)
            await db.commit()

        # Notify via WebSocket
        if user_id:
            await ws_manager.send_to_user(user_id, {
                "type": "scan_update",
                "scan_id": scan_id,
                "module": module_name,
                "status": "running",
                "target": target_value,
            })

        try:
            # Execute the scan
            logger.info("Executing scan", module=module_name, target=target_value)
            result = await module.scan(target_value, options)

            # Persist to database
            severity = result.severity if hasattr(result, 'severity') else "info"
            async with async_session() as db:
                await ScanEngine._update_scan_status(
                    db, scan_id, ScanStatus.completed,
                    summary=result.summary,
                    data=result.raw_data,
                    severity=severity,
                )
                await db.commit()

            # Index in Elasticsearch
            try:
                await ESClient.index_document(
                    INTEL_INDEX,
                    {
                        "case_id": target_case_id,
                        "target_id": target_id,
                        "module": module_name,
                        "entity_type": target_type,
                        "content": result.summary,
                        "raw_data": result.raw_data,
                        "severity": severity,
                        "tags": [e.entity_type for e in result.entities],
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    },
                    doc_id=scan_id,
                )
            except Exception as e:
                logger.warning("ES indexing failed (non-fatal)", error=str(e))

            # Store entities in Neo4j
            try:
                for entity in result.entities:
                    node = await Neo4jClient.create_entity(
                        entity.entity_type.capitalize(),
                        {
                            "value": entity.value,
                            "source": entity.source,
                            "confidence": entity.confidence,
                            "case_id": target_case_id,
                            **(entity.metadata if hasattr(entity, 'metadata') else {}),
                        },
                    )
                    # Link to target node
                    if target_neo4j_node_id and node.get("id"):
                        for rel in entity.relationships:
                            await Neo4jClient.create_relationship(
                                target_neo4j_node_id,
                                node["id"],
                                rel.get("type", "DISCOVERED"),
                                {"module": module_name},
                            )
            except Exception as e:
                logger.warning("Neo4j storage failed (non-fatal)", error=str(e))

            # Notify completion
            if user_id:
                await ws_manager.send_to_user(user_id, {
                    "type": "scan_update",
                    "scan_id": scan_id,
                    "module": module_name,
                    "status": "completed",
                    "target": target_value,
                    "summary": result.summary,
                    "entity_count": len(result.entities),
                    "severity": severity,
                })

            logger.info(
                "Scan completed",
                module=module_name,
                target=target_value,
                entities=len(result.entities),
            )
            return result

        except Exception as e:
            logger.error("Scan failed", module=module_name, error=str(e))
            async with async_session() as db:
                await ScanEngine._update_scan_status(
                    db, scan_id, ScanStatus.failed, error_message=str(e),
                )
                await db.commit()
            if user_id:
                await ws_manager.send_to_user(user_id, {
                    "type": "scan_update",
                    "scan_id": scan_id,
                    "module": module_name,
                    "status": "failed",
                    "error": str(e),
                })
            return None

    @staticmethod
    async def run_all_modules(
        target_value: str,
        target_type: str,
        target_case_id: str,
        target_neo4j_node_id: str,
        target_id: str,
        modules: List[str],
        scan_ids: List[str],
        options: Dict[str, Any],
        user_id: str = None,
    ) -> List[ModuleScanResult]:
        """Run multiple modules against a target sequentially.
        
        NOTE: This runs as a background task. It does NOT receive a db session;
        instead each execute_scan() creates its own session.
        """
        results = []
        for module_name, scan_id in zip(modules, scan_ids):
            result = await ScanEngine.execute_scan(
                scan_id=scan_id,
                target_value=target_value,
                target_type=target_type,
                target_case_id=target_case_id,
                target_neo4j_node_id=target_neo4j_node_id,
                target_id=target_id,
                module_name=module_name,
                options=options,
                user_id=user_id,
            )
            if result:
                results.append(result)

        # Run AI analysis on all results if available
        if results and ai_analyst.client:
            try:
                scan_data = [
                    {"module": r.module, "summary": r.summary, "data": r.raw_data}
                    for r in results
                ]
                analysis = await ai_analyst.analyze_scan_results(target_value, scan_data)
                if user_id:
                    await ws_manager.send_to_user(user_id, {
                        "type": "ai_analysis",
                        "target": target_value,
                        "analysis": analysis,
                    })
            except Exception as e:
                logger.warning("AI analysis skipped", error=str(e))

        return results

    @staticmethod
    async def _update_scan_status(
        db: AsyncSession,
        scan_id: str,
        status: ScanStatus,
        summary: str = None,
        data: dict = None,
        severity: str = None,
        error_message: str = None,
    ):
        """Update scan result in database."""
        result = await db.execute(
            select(ScanResult).where(ScanResult.id == scan_id)
        )
        scan = result.scalar_one_or_none()
        if scan:
            scan.status = status
            if summary:
                scan.summary = summary
            if data:
                scan.data = data
            if severity:
                scan.severity = severity
            if error_message:
                scan.error_message = error_message
            if status == ScanStatus.running:
                scan.started_at = datetime.now(timezone.utc)
            if status in (ScanStatus.completed, ScanStatus.failed):
                scan.completed_at = datetime.now(timezone.utc)
            await db.flush()


# Singleton
scan_engine = ScanEngine()
