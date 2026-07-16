from __future__ import annotations

from typing import Any, Optional

from sqlalchemy.orm import Session

from src.core.logging import logger
from src.models.sqlalchemy import AuditLog, User


class AuditService:
    def record(
        self,
        db: Session,
        *,
        action: str,
        user: Optional[User] = None,
        tenant_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        try:
            db.add(
                AuditLog(
                    tenant_id=tenant_id or (user.tenant_id if user else None),
                    user_id=user.id if user else None,
                    action=action,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    ip_address=ip_address,
                    details=details or {},
                )
            )
            db.commit()
        except Exception:
            db.rollback()
            logger.exception("Failed to write audit log for %s", action)


audit_service = AuditService()
