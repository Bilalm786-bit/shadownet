"""
ShadowNet — Alert Engine Service
Creates alerts from scan findings and sends notifications.
Supports: in-app alerts, with hooks for Telegram/Slack/Email.
"""

from typing import Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.models import Alert, SeverityLevel
from app.api.v1.websocket import ws_manager
import structlog

logger = structlog.get_logger(__name__)


class AlertEngine:
    """Generates and dispatches threat alerts."""

    @staticmethod
    async def create_alert(
        db: AsyncSession,
        title: str,
        message: str = None,
        severity: str = "info",
        source_module: str = None,
        case_id: str = None,
        data: Dict[str, Any] = None,
        notify_user_id: str = None,
    ) -> Alert:
        """Create an alert and optionally push via WebSocket."""
        alert = Alert(
            title=title,
            message=message,
            severity=severity,
            source_module=source_module,
            case_id=case_id,
            data=data or {},
        )
        db.add(alert)
        await db.flush()
        await db.refresh(alert)

        # Push real-time notification
        ws_payload = {
            "type": "alert",
            "alert_id": alert.id,
            "title": title,
            "severity": severity,
            "source_module": source_module,
            "message": message,
        }

        if notify_user_id:
            await ws_manager.send_to_user(notify_user_id, ws_payload)
        else:
            await ws_manager.broadcast(ws_payload)

        logger.info("Alert created", title=title, severity=severity)
        return alert

    @staticmethod
    async def alert_on_high_severity(
        db: AsyncSession,
        module: str,
        target: str,
        finding: str,
        case_id: str = None,
        user_id: str = None,
    ):
        """Auto-generate alert for high/critical severity findings."""
        await AlertEngine.create_alert(
            db=db,
            title=f"High-severity finding from {module}",
            message=f"Target: {target}\n{finding}",
            severity="high",
            source_module=module,
            case_id=case_id,
            notify_user_id=user_id,
        )

    @staticmethod
    async def alert_on_breach(
        db: AsyncSession,
        target: str,
        breach_count: int,
        case_id: str = None,
        user_id: str = None,
    ):
        """Alert when breach data is found for a target."""
        await AlertEngine.create_alert(
            db=db,
            title=f"Breach data found for {target}",
            message=f"{breach_count} breaches detected. Immediate review recommended.",
            severity="critical",
            source_module="breach.intelligence",
            case_id=case_id,
            notify_user_id=user_id,
        )

    @staticmethod
    async def alert_on_darkweb_mention(
        db: AsyncSession,
        target: str,
        mention_count: int,
        case_id: str = None,
        user_id: str = None,
    ):
        """Alert when target is mentioned on the dark web."""
        await AlertEngine.create_alert(
            db=db,
            title=f"Dark web mentions found for {target}",
            message=f"{mention_count} mentions discovered on onion sites.",
            severity="high",
            source_module="darkweb.onion_search",
            case_id=case_id,
            notify_user_id=user_id,
        )


# Singleton
alert_engine = AlertEngine()
