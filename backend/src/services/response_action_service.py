from __future__ import annotations
from sqlalchemy.orm import Session

from src.models.sqlalchemy import ResponseAction
from src.models.pydantic import ResponseActionCreate
from src.services.incident_service import incident_service


class UnsupportedResponseAction(ValueError):
    pass


class ResponseActionService:
    def list_actions(self, db: Session, tenant_id: str, incident_id: str) -> list[ResponseAction]:
        incident_service.get_incident_model(db, tenant_id, incident_id)
        return (
            db.query(ResponseAction)
            .filter(
                ResponseAction.tenant_id == tenant_id,
                ResponseAction.incident_id == incident_id,
            )
            .order_by(ResponseAction.created_at.desc())
            .all()
        )

    def create_action(
        self,
        db: Session,
        tenant_id: str,
        incident_id: str,
        user_id: str,
        action_data: ResponseActionCreate,
    ) -> ResponseAction:
        incident_service.get_incident_model(db, tenant_id, incident_id)
        raise UnsupportedResponseAction(
            "This endpoint has no action executor. Use a configured SOAR connector "
            "to execute response actions with approval and execution tracking."
        )


response_action_service = ResponseActionService()
