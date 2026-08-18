import asyncio
import time

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Path
from src.api.deps import get_current_user_ws
from src.services.websocket_service import manager
from src.core.logging import logger
from src.core.config import get_settings
from src.core.validation import UUID_PATTERN
from src.core.database import SessionLocal
from src.models.sqlalchemy import OrganizationMembership

router = APIRouter()
settings = get_settings()


async def _handle_websocket_connection(websocket: WebSocket, current_user):
    # Use tenant_id from authenticated user, NOT from user input!
    tenant_id = current_user.tenant_id
    permissions = getattr(current_user, "effective_permissions", set())
    if not permissions.intersection({"alerts.view", "incidents.view", "notifications.manage"}):
        await websocket.accept()
        await websocket.close(code=1008, reason="Unauthorized: Missing channel permission")
        return
    if not tenant_id:
        await websocket.accept()
        await websocket.close(code=1008, reason="Unauthorized: Missing tenant")
        logger.warning("WebSocket connection rejected because authenticated user has no tenant")
        return
    
    await manager.connect(websocket, tenant_id)
    try:
        while True:
            if getattr(current_user, "auth_expires_at", 0) <= time.time():
                await websocket.close(code=1008, reason="Authentication expired")
                manager.disconnect(websocket, tenant_id)
                return
            try:
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=settings.WEBSOCKET_HEARTBEAT_SECONDS,
                )
            except asyncio.TimeoutError:
                db = SessionLocal()
                try:
                    membership_active = db.query(OrganizationMembership).filter_by(
                        user_id=current_user.id,
                        tenant_id=tenant_id,
                        is_active=True,
                    ).first() is not None
                finally:
                    db.close()
                if not membership_active:
                    await websocket.close(code=1008, reason="Organization membership revoked")
                    manager.disconnect(websocket, tenant_id)
                    return
                if not await manager.heartbeat(websocket, tenant_id):
                    manager.disconnect(websocket, tenant_id)
                    return
                continue

            if data == "ping":
                try:
                    await asyncio.wait_for(
                        websocket.send_text("pong"),
                        timeout=settings.WEBSOCKET_SEND_TIMEOUT_SECONDS,
                    )
                except Exception:
                    logger.exception("WebSocket pong send failed")
                    manager.disconnect(websocket, tenant_id)
                    return
                continue
            logger.debug("WebSocket message received")
    except WebSocketDisconnect:
        manager.disconnect(websocket, tenant_id)
    except Exception:
        logger.exception("WebSocket connection error")
        manager.disconnect(websocket, tenant_id)


@router.websocket("/ws")
async def websocket_endpoint_new(
    websocket: WebSocket,
    current_user = Depends(get_current_user_ws)
):
    await _handle_websocket_connection(websocket, current_user)


@router.websocket("/ws/{tenant_id}")
async def websocket_endpoint_backward_compat(
    websocket: WebSocket,
    tenant_id: str = Path(..., description="Tenant ID (deprecated, use /ws instead)"),
    current_user = Depends(get_current_user_ws)
):
    # Validate that requested tenant_id matches authenticated user's tenant_id!
    if not UUID_PATTERN.match(tenant_id or "") or tenant_id != current_user.tenant_id:
        await websocket.accept()
        await websocket.close(code=1008, reason="Unauthorized: Invalid tenant ID")
        logger.warning(
            "WebSocket connection rejected for mismatched tenant",
            extra={"requested_tenant_id": tenant_id},
        )
        return
        
    await _handle_websocket_connection(websocket, current_user)
