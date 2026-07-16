from __future__ import annotations
from sqlalchemy.orm import Session, joinedload

from src.models.sqlalchemy import IncidentComment
from src.models.pydantic import IncidentCommentCreate
from src.services.incident_service import incident_service


class IncidentCommentService:
    def list_comments(
        self,
        db: Session,
        tenant_id: str,
        incident_id: str,
    ) -> list[IncidentComment]:
        incident_service.get_incident_model(db, tenant_id, incident_id)
        return (
            db.query(IncidentComment)
            .options(joinedload(IncidentComment.user))
            .filter(
                IncidentComment.tenant_id == tenant_id,
                IncidentComment.incident_id == incident_id,
            )
            .order_by(IncidentComment.created_at.asc())
            .all()
        )

    def create_comment(
        self,
        db: Session,
        tenant_id: str,
        incident_id: str,
        user_id: str,
        comment_data: IncidentCommentCreate,
    ) -> IncidentComment:
        incident_service.get_incident_model(db, tenant_id, incident_id)
        comment = IncidentComment(
            tenant_id=tenant_id,
            incident_id=incident_id,
            user_id=user_id,
            content=comment_data.content,
        )
        db.add(comment)
        db.commit()
        db.refresh(comment)
        comment = (
            db.query(IncidentComment)
            .options(joinedload(IncidentComment.user))
            .filter(IncidentComment.id == comment.id)
            .first()
        )
        return comment


incident_comment_service = IncidentCommentService()
