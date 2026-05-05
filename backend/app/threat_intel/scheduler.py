"""
ShadowNet — Threat Intelligence Scheduler
Periodically refreshes threat-intel feeds and broadcasts new IOCs via WebSocket.
Runs as a background asyncio task started during app lifespan.
"""

import asyncio
import structlog
from typing import Optional
from datetime import datetime, timezone

from app.threat_intel.feeds import threat_intel_aggregator

logger = structlog.get_logger(__name__)


class ThreatIntelScheduler:
    """Background scheduler that drives the threat-intel aggregator."""

    def __init__(self, refresh_interval: int = 600):
        # Default: refresh every 10 minutes
        self.refresh_interval = refresh_interval
        self._task: Optional[asyncio.Task] = None
        self._running = False

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info("Threat intel scheduler started", interval=self.refresh_interval)

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Threat intel scheduler stopped")

    async def _loop(self) -> None:
        # Initial delay so app boot isn't blocked
        await asyncio.sleep(5)
        # Initial light refresh (skip the heaviest/biggest feeds first time)
        try:
            await self._refresh_and_broadcast(initial=True)
        except Exception as e:
            logger.warning("Initial threat-intel refresh failed", error=str(e))

        while self._running:
            try:
                await asyncio.sleep(self.refresh_interval)
                if not self._running:
                    break
                await self._refresh_and_broadcast()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning("Threat-intel refresh loop error", error=str(e))
                await asyncio.sleep(30)

    async def _refresh_and_broadcast(self, initial: bool = False) -> None:
        # On the initial pass, exclude very large feeds to avoid slow startup.
        if initial:
            feeds = ["urlhaus", "threatfox", "feodo", "openphish",
                     "cisa_kev", "nvd", "otx", "spamhaus"]
        else:
            feeds = None  # all
        result = await threat_intel_aggregator.refresh(feeds=feeds)

        # Broadcast a summary tick + each fresh indicator (capped) via WebSocket
        try:
            from app.api.v1.websocket import ws_manager
        except Exception:
            return

        await ws_manager.broadcast({
            "type": "threat_intel_refresh",
            "total": result["total"],
            "fresh": result["fresh"],
            "feed_status": result["status"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        for ind in result["fresh_indicators"][:25]:
            await ws_manager.broadcast({
                "type": "threat_indicator",
                "indicator": ind,
                "timestamp": ind.get("first_seen") or datetime.now(timezone.utc).isoformat(),
            })


# Singleton
threat_intel_scheduler = ThreatIntelScheduler(refresh_interval=600)
