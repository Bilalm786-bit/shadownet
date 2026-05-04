"""
ShadowNet — WebSocket Real-time Intel Feed
Pushes scan updates and alerts to connected frontend clients.
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from typing import Dict, Set
import json
import structlog

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["WebSocket"])


class ConnectionManager:
    """Manages WebSocket connections for real-time intel feed."""

    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {}  # user_id -> websockets

    async def connect(self, websocket: WebSocket, user_id: str):
        await websocket.accept()
        if user_id not in self.active_connections:
            self.active_connections[user_id] = set()
        self.active_connections[user_id].add(websocket)
        logger.info("WebSocket connected", user_id=user_id, total=len(self.active_connections))

    def disconnect(self, websocket: WebSocket, user_id: str):
        if user_id in self.active_connections:
            self.active_connections[user_id].discard(websocket)
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]
        logger.info("WebSocket disconnected", user_id=user_id)

    async def send_to_user(self, user_id: str, message: dict):
        """Send a message to all connections of a specific user."""
        if user_id in self.active_connections:
            dead = set()
            for ws in self.active_connections[user_id]:
                try:
                    await ws.send_json(message)
                except Exception:
                    dead.add(ws)
            self.active_connections[user_id] -= dead

    async def broadcast(self, message: dict):
        """Broadcast a message to all connected clients."""
        for user_id in list(self.active_connections.keys()):
            await self.send_to_user(user_id, message)


# Singleton
ws_manager = ConnectionManager()


@router.websocket("/ws/feed")
async def websocket_feed(websocket: WebSocket):
    """WebSocket endpoint for real-time intel feed."""
    # Simple auth via query param (in production, validate JWT)
    user_id = websocket.query_params.get("user_id", "anonymous")
    await ws_manager.connect(websocket, user_id)

    try:
        while True:
            # Keep connection alive, receive commands from client
            data = await websocket.receive_text()
            try:
                message = json.loads(data)
                # Handle client commands (subscribe to case, etc.)
                if message.get("type") == "subscribe_case":
                    case_id = message.get("case_id")
                    await websocket.send_json({
                        "type": "subscribed",
                        "case_id": case_id,
                        "message": f"Now receiving updates for case {case_id}",
                    })
                elif message.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, user_id)
