from __future__ import annotations
from sqlalchemy.orm import Session

from src.models.sqlalchemy import Notification, NotificationType, User
from src.models.pydantic import NotificationUpdateRead


class NotificationService:
    def list_notifications(
        self,
        db: Session,
        tenant_id: str,
        user_id: str,
        is_read: bool | None = None,
    ) -> list[Notification]:
        query = db.query(Notification).filter(
            Notification.tenant_id == tenant_id,
            Notification.user_id == user_id,
        )
        if is_read is not None:
            query = query.filter(Notification.is_read == is_read)
        return query.order_by(Notification.created_at.desc()).all()

    def create_notification(
        self,
        db: Session,
        tenant_id: str,
        user_id: str,
        title: str,
        message: str | None = None,
        notif_type: NotificationType = NotificationType.INFO,
    ) -> Notification:
        notif = Notification(
            tenant_id=tenant_id,
            user_id=user_id,
            title=title,
            message=message,
            type=notif_type,
            is_read=False,
        )
        db.add(notif)
        db.commit()
        db.refresh(notif)
        return notif

    def update_read_status(
        self,
        db: Session,
        tenant_id: str,
        user_id: str,
        notification_id: str,
        update_data: NotificationUpdateRead,
    ) -> Notification:
        notif = db.query(Notification).filter(
            Notification.id == notification_id,
            Notification.tenant_id == tenant_id,
            Notification.user_id == user_id,
        ).first()
        if not notif:
            raise ValueError("Notification not found")
        notif.is_read = update_data.is_read
        db.add(notif)
        db.commit()
        db.refresh(notif)
        return notif


notification_service = NotificationService()
