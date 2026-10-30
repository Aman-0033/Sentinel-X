"""Real-time WebSocket dashboard broadcast endpoint (Section 23)."""

import json
import logging
from typing import List, Optional

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status

from app.core.security import decode_access_token
from app.db.session import SessionLocal
from app.repositories.users import UserRepository

logger = logging.getLogger("sentinel.ws")
router = APIRouter(tags=["WebSocket"])


class ConnectionManager:
    """Manages active authenticated WebSocket connections for the SOC dashboard."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Total active: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(
                f"WebSocket client disconnected. Total active: {len(self.active_connections)}"
            )

    async def broadcast(self, event_type: str, data: dict) -> None:
        """Broadcast structured event to all active dashboard clients."""
        payload = json.dumps({"event": event_type, "data": data})
        for connection in list(self.active_connections):
            try:
                await connection.send_text(payload)
            except Exception:
                self.disconnect(connection)


# Global connection manager singleton
ws_manager = ConnectionManager()


@router.websocket("/ws/dashboard")
async def websocket_dashboard(
    websocket: WebSocket,
    token: Optional[str] = Query(None),
) -> None:
    """Authenticated WebSocket endpoint for real-time dashboard telemetry and threat alerts."""
    # 1. Authenticate via token query parameter or Authorization header
    auth_token = token
    if not auth_token:
        # Check Sec-WebSocket-Protocol or headers
        auth_header = websocket.headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            auth_token = auth_header.split(" ", 1)[1]

    if not auth_token:
        logger.warning("WebSocket connection rejected: Missing authentication token.")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    try:
        payload = decode_access_token(auth_token)
        user_id = payload.get("sub")
        if not user_id:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        db = SessionLocal()
        try:
            user = UserRepository(db).get_by_id(user_id)
            if not user or not user.is_active:
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                return
        finally:
            db.close()

    except Exception as exc:
        logger.warning(f"WebSocket authentication failed: {str(exc)}")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # 2. Connection accepted
    await ws_manager.connect(websocket)
    try:
        # Send initial connection confirmation
        await websocket.send_text(
            json.dumps(
                {
                    "event": "CONNECTED",
                    "data": {"message": "Authenticated to Sentinel-X SOC Live Feed"},
                }
            )
        )

        while True:
            # Keep connection open, handle client heartbeats
            data = await websocket.receive_text()
            if data.strip().upper() == "PING":
                await websocket.send_text(json.dumps({"event": "PONG"}))

    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as exc:
        logger.warning(f"WebSocket connection error: {str(exc)}")
        ws_manager.disconnect(websocket)
