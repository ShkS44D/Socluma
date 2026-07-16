from __future__ import annotations
from sqlalchemy.orm import Session

from src.models.sqlalchemy import ResponseAction, IncidentStatus
from src.models.pydantic import ResponseActionCreate
from src.services.incident_service import incident_service


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
        action = ResponseAction(
            tenant_id=tenant_id,
            incident_id=incident_id,
            action_type=action_data.action_type,
            executed_by=user_id,
            details=action_data.details,
        )
        db.add(action)
        db.commit()
        db.refresh(action)

        # Simulation of action execution
        from src.models.sqlalchemy import ActionStatus
        action.status = ActionStatus.RUNNING
        db.add(action)
        db.commit()

        action.status = ActionStatus.COMPLETED
        db.add(action)
        db.commit()
        db.refresh(action)

        return action


response_action_service = ResponseActionService()
