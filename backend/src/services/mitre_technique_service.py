from __future__ import annotations
from typing import Optional
from sqlalchemy.orm import Session

from src.models.sqlalchemy import MitreTechnique, MitreTactic
from src.models.pydantic import MitreTechniqueCreate


class MitreTechniqueService:
    def list_techniques(
        self,
        db: Session,
        tactic: Optional[MitreTactic] = None,
    ) -> list[MitreTechnique]:
        query = db.query(MitreTechnique)
        if tactic:
            query = query.filter(MitreTechnique.tactic == tactic)
        return query.order_by(MitreTechnique.created_at.desc()).all()

    def get_technique_by_id(self, db: Session, technique_id: str) -> MitreTechnique:
        technique = db.query(MitreTechnique).filter(MitreTechnique.id == technique_id).first()
        if not technique:
            raise ValueError("MITRE technique not found")
        return technique

    def create_technique(
        self,
        db: Session,
        technique_data: MitreTechniqueCreate,
    ) -> MitreTechnique:
        technique = MitreTechnique(
            technique_id=technique_data.technique_id,
            name=technique_data.name,
            tactic=technique_data.tactic,
            description=technique_data.description,
        )
        db.add(technique)
        db.commit()
        db.refresh(technique)
        return technique


mitre_technique_service = MitreTechniqueService()
