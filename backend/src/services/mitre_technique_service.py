from __future__ import annotations
import json
import logging
from pathlib import Path
from typing import Iterable, Optional
from sqlalchemy.orm import Session

from src.models.sqlalchemy import MitreTechnique, MitreTactic
from src.models.pydantic import MitreTechniqueCreate


class MitreTechniqueService:
    CATALOG_PATH = Path(__file__).resolve().parent.parent / "data" / "mitre_enterprise_v18_1.json"
    logger = logging.getLogger(__name__)

    def load_catalog(self) -> dict:
        with self.CATALOG_PATH.open(encoding="utf-8") as handle:
            return json.load(handle)

    def resolve(self, db: Session, technique_id: str) -> Optional[MitreTechnique]:
        row = db.query(MitreTechnique).filter(MitreTechnique.technique_id == technique_id).first()
        if row is None:
            self.logger.warning("Unresolved MITRE ATT&CK metadata", extra={"technique_id": technique_id})
        return row

    def bootstrap_catalog(self, db: Session, technique_ids: Optional[Iterable[str]] = None) -> dict[str, int]:
        catalog = self.load_catalog()
        requested = set(technique_ids or ())
        records = [item for item in catalog["techniques"] if not requested or item["technique_id"] in requested]
        created = updated = 0
        for item in records:
            row = db.query(MitreTechnique).filter(MitreTechnique.technique_id == item["technique_id"]).first()
            if row is None:
                row = MitreTechnique(technique_id=item["technique_id"], name=item["name"], tactic=MitreTactic(item["tactic"]))
                db.add(row)
                created += 1
            else:
                updated += 1
            for field in (
                "name", "description", "tactic_id", "tactic_order", "tactics", "parent_technique_id",
                "parent_technique_name", "sub_technique_id", "sub_technique_name", "is_subtechnique",
                "is_revoked", "is_deprecated", "catalog_version", "catalog_source", "external_url",
            ):
                setattr(row, field, item.get(field))
            row.tactic = MitreTactic(item["tactic"])
        db.commit()
        return {"created": created, "updated": updated, "total": len(records)}

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
            tactic_id=technique_data.tactic_id,
            tactic_order=technique_data.tactic_order,
            tactics=technique_data.tactics,
            parent_technique_id=technique_data.parent_technique_id,
            parent_technique_name=technique_data.parent_technique_name,
            sub_technique_id=technique_data.sub_technique_id,
            sub_technique_name=technique_data.sub_technique_name,
            is_subtechnique=technique_data.is_subtechnique,
            is_revoked=technique_data.is_revoked,
            is_deprecated=technique_data.is_deprecated,
            catalog_version=technique_data.catalog_version,
            catalog_source=technique_data.catalog_source,
            external_url=technique_data.external_url,
        )
        db.add(technique)
        db.commit()
        db.refresh(technique)
        return technique


mitre_technique_service = MitreTechniqueService()
