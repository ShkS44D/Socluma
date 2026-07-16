from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from typing import Optional

from src.api.deps import get_db, get_current_user
from src.models.pydantic import Notification, NotificationUpdateRead
from src.models.sqlalchemy import User
from src.services.notification_service import notification_service


router = APIRouter(prefix="/notifications", tags=["Notifications"])


@router.get("", response_model=list[Notification])
def list_notifications(
    is_read: Optional[bool] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    notifications = notification_service.list_notifications(
        db, current_user.tenant_id, current_user.id, is_read=is_read
    )
    return [Notification.model_validate(notif) for notif in notifications]


@router.patch("/{notification_id}/read", response_model=Notification)
def update_notification_read_status(
    notification_id: str,
    update_data: NotificationUpdateRead,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        notif = notification_service.update_read_status(
            db, current_user.tenant_id, current_user.id, notification_id, update_data
        )
        return Notification.model_validate(notif)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e
