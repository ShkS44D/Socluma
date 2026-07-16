from fastapi import WebSocket
from typing import Dict, Set
import asyncio
from src.core.config import get_settings
from src.utils.datetime_utils import get_utc_now, utc_isoformat
from src.core.logging import logger
from src.core.observability import WEBSOCKET_CONNECTIONS, WEBSOCKET_EVENTS

settings = get_settings()


class ConnectionManager:
    def __init__(self):
        # Dictionary mapping tenant_id to set of WebSocket connections
        self.active_connections: Dict[str, Set[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, tenant_id: str):
        await websocket.accept()
        if tenant_id not in self.active_connections:
            self.active_connections[tenant_id] = set()
        self.active_connections[tenant_id].add(websocket)
        WEBSOCKET_CONNECTIONS.inc()
        WEBSOCKET_EVENTS.labels("connected").inc()
        logger.info("WebSocket connected: tenant=%s total=%s", tenant_id, len(self.active_connections[tenant_id]))

    def disconnect(self, websocket: WebSocket, tenant_id: str):
        if tenant_id in self.active_connections:
            before = len(self.active_connections[tenant_id])
            self.active_connections[tenant_id].discard(websocket)
            if before != len(self.active_connections[tenant_id]):
                WEBSOCKET_CONNECTIONS.dec()
                WEBSOCKET_EVENTS.labels("disconnected").inc()
            if not self.active_connections[tenant_id]:
                del self.active_connections[tenant_id]
            logger.info("WebSocket disconnected: tenant=%s remaining=%s", tenant_id, len(self.active_connections.get(tenant_id, [])))

    async def send_personal_message(self, message: dict, websocket: WebSocket) -> bool:
        try:
            await asyncio.wait_for(websocket.send_json(message), timeout=settings.WEBSOCKET_SEND_TIMEOUT_SECONDS)
            return True
        except Exception:
            logger.exception("WebSocket personal message failed")
            return False

    async def broadcast(self, message: dict, tenant_id: str):
        connections = list(self.active_connections.get(tenant_id, set()))
        if not connections:
            return

        async def _send(connection: WebSocket) -> WebSocket | None:
            try:
                await asyncio.wait_for(connection.send_json(message), timeout=settings.WEBSOCKET_SEND_TIMEOUT_SECONDS)
                WEBSOCKET_EVENTS.labels("broadcast").inc()
                return None
            except Exception:
                logger.exception("WebSocket broadcast failed")
                return connection

        results = await asyncio.gather(*(_send(connection) for connection in connections), return_exceptions=True)
        disconnected = set()
        for result in results:
            if isinstance(result, WebSocket):
                disconnected.add(result)
            elif isinstance(result, Exception):
                logger.error(
                    "Unexpected WebSocket broadcast task failure",
                    exc_info=(type(result), result, result.__traceback__),
                )
        for connection in disconnected:
            self.disconnect(connection, tenant_id)

    async def heartbeat(self, websocket: WebSocket, tenant_id: str) -> bool:
        sent = await self.send_personal_message(
            {
                "type": "heartbeat",
                "data": {"tenant_id": tenant_id},
                "timestamp": utc_isoformat(get_utc_now()),
            },
            websocket,
        )
        if sent:
            WEBSOCKET_EVENTS.labels("heartbeat").inc()
        return sent


# Global instance
manager = ConnectionManager()


class NotificationType:
    NEW_EVENT = "new_event"
    NEW_ALERT = "new_alert"
    NEW_INCIDENT = "new_incident"
    IOC_UPDATE = "ioc_update"


async def broadcast_notification(tenant_id: str, notification_type: str, data: dict):
    message = {
        "type": notification_type,
        "data": data,
        "timestamp": utc_isoformat(get_utc_now())
    }
    await manager.broadcast(message, tenant_id)


def broadcast_notification_sync(tenant_id: str, notification_type: str, data: dict):
    """Helper function to broadcast from synchronous code"""
    try:
        loop = asyncio.get_running_loop()
        asyncio.create_task(broadcast_notification(tenant_id, notification_type, data))
    except RuntimeError:
        # If no event loop is running, create a new one
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            loop.run_until_complete(broadcast_notification(tenant_id, notification_type, data))
        except Exception:
            logger.exception(
                "Synchronous WebSocket notification broadcast failed",
                extra={"tenant_id": tenant_id, "notification_type": notification_type},
            )
        finally:
            loop.close()
    except Exception:
        logger.exception(
            "WebSocket notification scheduling failed",
            extra={"tenant_id": tenant_id, "notification_type": notification_type},
        )
