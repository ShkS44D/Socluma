from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import Optional

from src.api.deps import get_db
from src.core.permissions import Permission, require_permission
from src.models.pydantic import MitreTechnique, MitreTechniqueCreate
from src.models.sqlalchemy import MitreTactic, User
from src.services.mitre_technique_service import mitre_technique_service


router = APIRouter(prefix="/mitre-techniques", tags=["MITRE Techniques"])


@router.post("", response_model=MitreTechnique, status_code=status.HTTP_201_CREATED)
def create_technique(
    technique_data: MitreTechniqueCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.DETECTIONS_UPDATE)),
):
    technique = mitre_technique_service.create_technique(db, technique_data)
    return MitreTechnique.model_validate(technique)


@router.get("", response_model=list[MitreTechnique])
def list_techniques(
    tactic: Optional[MitreTactic] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.DETECTIONS_VIEW)),
):
    techniques = mitre_technique_service.list_techniques(db, tactic=tactic)
    return [MitreTechnique.model_validate(technique) for technique in techniques]


@router.get("/{technique_id}", response_model=MitreTechnique)
def get_technique(
    technique_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.DETECTIONS_VIEW)),
):
    try:
        technique = mitre_technique_service.get_technique_by_id(db, technique_id)
        return MitreTechnique.model_validate(technique)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e
