from datetime import datetime, timedelta
from typing import Any
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from src.api.deps import get_db
from src.core.config import get_settings
from src.core.permissions import Permission, membership_permissions, require_any_permission, require_permission
from src.models.sqlalchemy import (
    Alert, Classification, DataSource, DetectionContentPack, DetectionException, DetectionMaintenanceWindow, DetectionMatch,
    DetectionRecommendation, DetectionRule, DetectionRuleHealthSnapshot, DetectionRuleVersion,
    DetectionRuleTestCase, DetectionRuleTestResult, DetectionSimulationJob,
    DetectionSuppressionPolicy, Feedback, Incident, SecurityEvent, User,
)
from src.services.audit_service import audit_service
from src.services.detection_lifecycle_service import DetectionLifecycleError, detection_lifecycle_service
from src.utils.datetime_utils import ensure_utc, get_utc_now

router = APIRouter(prefix="/detection-engineering", tags=["Detection Engineering"])

class VersionCreate(BaseModel):
    definition: dict[str, Any]
    original_content: str | None = Field(default=None, max_length=262144)
    change_summary: str | None = Field(default=None, max_length=2000)

class TransitionRequest(BaseModel):
    target: str
    comment: str | None = Field(default=None, max_length=2000)
    reviewer_id: str | None = None

class SimulationCreate(BaseModel):
    start: datetime
    end: datetime
    event_limit: int = Field(default=10000, ge=1)

class ExceptionCreate(BaseModel):
    rule_id: str | None = None
    name: str = Field(min_length=1,max_length=150)
    reason: str = Field(min_length=1,max_length=2000)
    criteria: dict[str,Any]
    starts_at: datetime | None = None
    expires_at: datetime

class MaintenanceCreate(BaseModel):
    name: str = Field(min_length=1,max_length=150)
    reason: str = Field(min_length=1,max_length=2000)
    scope: dict[str,Any]
    starts_at: datetime
    ends_at: datetime
    timezone: str = Field(default="UTC",max_length=80)

class ContentPackRequest(BaseModel):
    manifest: dict[str,Any]
    dry_run: bool = True

class TestCaseCreate(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    input_events: list[dict[str, Any]] = Field(min_length=1)
    expected: dict[str, Any]

class SuppressionCreate(BaseModel):
    rule_id: str
    grouping_fields: list[str] = Field(default_factory=list, max_length=5)
    window_seconds: int = Field(default=300, ge=10, le=86400)
    maximum_alerts: int = Field(default=1, ge=1, le=10000)
    cooldown_seconds: int = Field(default=0, ge=0, le=86400)
    enabled: bool = True

def _rule(db, tenant, identity):
    row = db.query(DetectionRule).filter_by(id=identity, tenant_id=tenant).first()
    if not row:
        raise HTTPException(404, detail={"error_code":"DETECTION_RULE_NOT_FOUND","message":"Rule not found"})
    return row

def _version(db, tenant, identity):
    row = db.query(DetectionRuleVersion).filter_by(id=identity, tenant_id=tenant).first()
    if not row:
        raise HTTPException(404, detail={"error_code":"DETECTION_VERSION_NOT_FOUND","message":"Version not found"})
    return row

@router.post("/validate")
def validate(payload: VersionCreate, db: Session=Depends(get_db), user: User=Depends(require_permission(Permission.DETECTIONS_UPDATE))):
    return detection_lifecycle_service.validate(payload.definition, sigma_content=payload.original_content, db=db)

@router.get("/rules/{rule_id}/versions")
def versions(rule_id: str, db: Session=Depends(get_db), user: User=Depends(require_permission(Permission.DETECTIONS_VIEW))):
    _rule(db,user.tenant_id,rule_id)
    return db.query(DetectionRuleVersion).filter_by(tenant_id=user.tenant_id,rule_id=rule_id).order_by(DetectionRuleVersion.version_number.desc()).all()

@router.post("/rules/{rule_id}/versions",status_code=201)
def create_version(rule_id: str,payload: VersionCreate,db: Session=Depends(get_db),user: User=Depends(require_permission(Permission.DETECTIONS_UPDATE))):
    rule=_rule(db,user.tenant_id,rule_id)
    report=detection_lifecycle_service.validate(payload.definition,sigma_content=payload.original_content if rule.rule_type.value=="sigma" else None,db=db)
    if not report["valid"]:
        raise HTTPException(422,detail={"error_code":"DETECTION_VALIDATION_FAILED","message":"Validation failed","details":report})
    row=detection_lifecycle_service.create_version(db,rule,user.id,payload.definition,original_content=payload.original_content,summary=payload.change_summary)
    db.commit();db.refresh(row)
    audit_service.record(db,action="detection_version_created",user=user,resource_type="detection_rule_version",resource_id=row.id,details={"content_hash":row.content_hash})
    return row

@router.post("/versions/{version_id}/transition")
def transition(version_id: str,payload: TransitionRequest,db: Session=Depends(get_db),user: User=Depends(require_any_permission(Permission.DETECTIONS_UPDATE, Permission.DETECTIONS_VALIDATE, Permission.DETECTIONS_TEST, Permission.DETECTIONS_REVIEW, Permission.DETECTIONS_APPROVE, Permission.DETECTIONS_PUBLISH, Permission.DETECTIONS_ENABLE, Permission.DETECTIONS_DISABLE, Permission.DETECTIONS_RETIRE))):
    version=_version(db,user.tenant_id,version_id);rule=_rule(db,user.tenant_id,version.rule_id)
    if payload.reviewer_id:
        detection_lifecycle_service.assert_member(db,user.tenant_id,payload.reviewer_id)
        version.reviewer_id=payload.reviewer_id
    required = {
        "validating": Permission.DETECTIONS_VALIDATE.value,
        "ready_for_review": Permission.DETECTIONS_UPDATE.value,
        "under_review": Permission.DETECTIONS_REVIEW.value,
        "approved": Permission.DETECTIONS_APPROVE.value,
        "production": Permission.DETECTIONS_PUBLISH.value,
        "disabled": Permission.DETECTIONS_DISABLE.value,
        "retired": Permission.DETECTIONS_RETIRE.value,
        "archived": Permission.DETECTIONS_RETIRE.value,
        "changes_requested": Permission.DETECTIONS_REVIEW.value,
        "test_failed": Permission.DETECTIONS_TEST.value,
        "draft": Permission.DETECTIONS_UPDATE.value,
    }.get(payload.target)
    if required and required not in membership_permissions(db, user):
        raise HTTPException(403, detail={"error_code":"DETECTION_TRANSITION_DENIED","message":"Permission denied for this transition"})
    try:detection_lifecycle_service.transition(db,rule,version,payload.target,user,comment=payload.comment)
    except DetectionLifecycleError as exc:
        raise HTTPException(409,detail={"error_code":exc.code,"message":exc.message}) from exc
    db.commit();db.refresh(version)
    audit_service.record(db,action="detection_lifecycle_transition",user=user,resource_type="detection_rule_version",resource_id=version.id,details={"target":payload.target,"content_hash":version.content_hash})
    return version

@router.post("/versions/{version_id}/clone",status_code=201)
def clone_version(version_id: str,payload: VersionCreate | None=None,db: Session=Depends(get_db),user: User=Depends(require_permission(Permission.DETECTIONS_CLONE))):
    source=_version(db,user.tenant_id,version_id);rule=_rule(db,user.tenant_id,source.rule_id)
    row=detection_lifecycle_service.create_version(db,rule,user.id,source.normalized_definition,original_content=source.original_content,summary=(payload.change_summary if payload else None) or f"Cloned from version {source.version_number}")
    db.commit();db.refresh(row)
    return row

@router.post("/versions/{version_id}/rollback",status_code=201)
def rollback_version(version_id: str,db: Session=Depends(get_db),user: User=Depends(require_permission(Permission.DETECTIONS_ROLLBACK))):
    source=_version(db,user.tenant_id,version_id);rule=_rule(db,user.tenant_id,source.rule_id)
    row=detection_lifecycle_service.create_version(db,rule,user.id,source.normalized_definition,original_content=source.original_content,summary=f"Rollback candidate from version {source.version_number}")
    row.source_metadata={"rollback_source_version_id":source.id,"rollback_source_hash":source.content_hash}
    db.commit();db.refresh(row)
    return row

def _mask_test_value(value: Any, key: str = "") -> Any:
    if any(token in key.casefold() for token in ("password", "secret", "token", "credential")):
        return "***"
    if isinstance(value, dict):
        return {item_key: _mask_test_value(item_value, item_key) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [_mask_test_value(item) for item in value]
    return value

@router.post("/versions/{version_id}/tests", status_code=201)
def create_and_run_test(version_id: str,payload: TestCaseCreate,db: Session=Depends(get_db),user: User=Depends(require_permission(Permission.DETECTIONS_TEST))):
    version=_version(db,user.tenant_id,version_id)
    limit=get_settings().DETECTION_TEST_DATASET_MAX_EVENTS
    if len(payload.input_events)>limit:
        raise HTTPException(413,detail={"error_code":"DETECTION_TEST_DATASET_TOO_LARGE","message":"Test dataset exceeds event limit"})
    import hashlib,json
    masked=_mask_test_value(payload.input_events)
    digest=hashlib.sha256(json.dumps(masked,sort_keys=True,separators=(",",":"),default=str).encode()).hexdigest()
    case=DetectionRuleTestCase(tenant_id=user.tenant_id,version_id=version.id,name=payload.name,input_events=masked,expected=payload.expected,content_hash=digest,created_by_id=user.id)
    db.add(case);db.flush()
    result=detection_lifecycle_service.evaluate_events(version.normalized_definition,[
        type("TestEvent",(),{
            "id":item.get("id",f"test-{index}"),"timestamp":ensure_utc(datetime.fromisoformat(item["timestamp"].replace("Z","+00:00"))) if item.get("timestamp") else get_utc_now(),
            "source":item.get("source","test"),"severity":item.get("severity","medium"),
            "normalized_event":item.get("normalized_event") or item,"raw_event":item.get("raw_event") or {},
        })() for index,item in enumerate(masked)
    ])
    expected_count=int(payload.expected.get("match_count",payload.expected.get("minimum_matches",1)))
    passed=result["matches"]==expected_count if "match_count" in payload.expected else result["matches"]>=expected_count
    row=DetectionRuleTestResult(tenant_id=user.tenant_id,version_id=version.id,test_case_id=case.id,status="passed" if passed else "failed",actual=result,safe_message=None if passed else "Expected result did not match",duration_ms=result["duration_ms"],run_by_id=user.id)
    db.add(row)
    version.test_result={"status":row.status,"last_result_id":row.id,"content_hash":digest}
    rule=_rule(db,user.tenant_id,version.rule_id);rule.last_tested_at=get_utc_now()
    db.commit();db.refresh(row)
    audit_service.record(db,action="detection_test_executed",user=user,resource_type="detection_rule_version",resource_id=version.id,details={"test_result_id":row.id,"status":row.status,"content_hash":case.content_hash})
    return row

@router.get("/versions/{version_id}/tests")
def list_tests(version_id: str,db: Session=Depends(get_db),user: User=Depends(require_permission(Permission.DETECTIONS_VIEW))):
    _version(db,user.tenant_id,version_id)
    return db.query(DetectionRuleTestResult).filter_by(tenant_id=user.tenant_id,version_id=version_id).order_by(DetectionRuleTestResult.created_at.desc()).limit(200).all()

@router.post("/versions/{version_id}/simulations",status_code=202)
def simulate(version_id: str,payload: SimulationCreate,db: Session=Depends(get_db),user: User=Depends(require_permission(Permission.DETECTIONS_SIMULATE))):
    version=_version(db,user.tenant_id,version_id);start,end=ensure_utc(payload.start),ensure_utc(payload.end);settings=get_settings()
    if start>=end or end-start>timedelta(days=settings.DETECTION_SIMULATION_MAX_DAYS) or payload.event_limit>settings.DETECTION_SIMULATION_MAX_EVENTS:
        raise HTTPException(422,detail={"error_code":"DETECTION_SIMULATION_LIMIT_EXCEEDED","message":"Simulation limits exceeded"})
    job=DetectionSimulationJob(tenant_id=user.tenant_id,version_id=version.id,requested_by_id=user.id,status="queued",time_start=start,time_end=end,event_limit=payload.event_limit,expires_at=get_utc_now()+timedelta(hours=settings.DETECTION_SIMULATION_EXPIRE_HOURS))
    db.add(job);db.commit();db.refresh(job)
    from src.workers.tasks import run_detection_simulation
    run_detection_simulation.delay(job.id,user.tenant_id)
    audit_service.record(db,action="detection_simulation_requested",user=user,resource_type="detection_simulation",resource_id=job.id,details={"version_id":version.id,"event_limit":payload.event_limit})
    return job

@router.get("/simulations/{job_id}")
def get_simulation(job_id: str,db: Session=Depends(get_db),user: User=Depends(require_permission(Permission.DETECTIONS_SIMULATE))):
    row=db.query(DetectionSimulationJob).filter_by(id=job_id,tenant_id=user.tenant_id).first()
    if not row:raise HTTPException(404,detail={"error_code":"DETECTION_SIMULATION_NOT_READY","message":"Simulation not found"})
    return row

@router.post("/simulations/{job_id}/cancel")
def cancel_simulation(job_id: str,db: Session=Depends(get_db),user: User=Depends(require_permission(Permission.DETECTIONS_SIMULATE))):
    row=db.query(DetectionSimulationJob).filter_by(id=job_id,tenant_id=user.tenant_id).first()
    if not row:raise HTTPException(404,detail={"error_code":"DETECTION_SIMULATION_NOT_READY","message":"Simulation not found"})
    if row.status in {"queued","running"}:row.cancel_requested=True;row.status="cancelled";row.completed_at=get_utc_now();db.commit()
    audit_service.record(db,action="detection_simulation_cancelled",user=user,resource_type="detection_simulation",resource_id=row.id)
    return row

@router.post("/suppression-policies",status_code=201)
def upsert_suppression(payload: SuppressionCreate,db: Session=Depends(get_db),user: User=Depends(require_permission(Permission.DETECTIONS_EXCEPTIONS_MANAGE))):
    _rule(db,user.tenant_id,payload.rule_id)
    for field in payload.grouping_fields:
        if field not in __import__("src.services.search_query_service",fromlist=["SEARCH_FIELDS"]).SEARCH_FIELDS:
            raise HTTPException(422,detail={"error_code":"DETECTION_FIELD_UNSUPPORTED","message":f"Unsupported grouping field {field}"})
    row=db.query(DetectionSuppressionPolicy).filter_by(tenant_id=user.tenant_id,rule_id=payload.rule_id).first()
    if not row:row=DetectionSuppressionPolicy(tenant_id=user.tenant_id,created_by_id=user.id,**payload.model_dump());db.add(row)
    else:
        for key,value in payload.model_dump(exclude={"rule_id"}).items():setattr(row,key,value)
    db.commit();db.refresh(row)
    audit_service.record(db,action="detection_suppression_policy_changed",user=user,resource_type="detection_suppression_policy",resource_id=row.id,details={"rule_id":row.rule_id,"enabled":row.enabled})
    return row

@router.get("/suppression-policies")
def suppression_policies(db: Session=Depends(get_db),user: User=Depends(require_permission(Permission.DETECTIONS_EXCEPTIONS_VIEW))):
    return db.query(DetectionSuppressionPolicy).filter_by(tenant_id=user.tenant_id).limit(500).all()

@router.post("/exceptions",status_code=201)
def create_exception(payload: ExceptionCreate,db: Session=Depends(get_db),user: User=Depends(require_permission(Permission.DETECTIONS_EXCEPTIONS_MANAGE))):
    if payload.rule_id:_rule(db,user.tenant_id,payload.rule_id)
    expiry=ensure_utc(payload.expires_at);now=get_utc_now()
    allowed=set(payload.criteria).issubset({"field","operator","value","entity_type","cidr"})
    if not payload.criteria or not allowed or expiry<=now or expiry-now>timedelta(days=get_settings().DETECTION_EXCEPTION_MAX_DAYS):
        raise HTTPException(422,detail={"error_code":"DETECTION_EXCEPTION_INVALID","message":"Exception criteria or expiry is invalid"})
    row=DetectionException(tenant_id=user.tenant_id,created_by_id=user.id,**payload.model_dump())
    db.add(row);db.commit();db.refresh(row)
    audit_service.record(db,action="detection_exception_created",user=user,resource_type="detection_exception",resource_id=row.id,details={"rule_id":row.rule_id,"expires_at":row.expires_at})
    return row

@router.get("/exceptions")
def exceptions(db: Session=Depends(get_db),user: User=Depends(require_permission(Permission.DETECTIONS_VIEW))):
    return db.query(DetectionException).filter_by(tenant_id=user.tenant_id).order_by(DetectionException.expires_at).limit(500).all()

@router.post("/exceptions/{exception_id}/cancel")
def cancel_exception(exception_id: str,db: Session=Depends(get_db),user: User=Depends(require_permission(Permission.DETECTIONS_EXCEPTIONS_MANAGE))):
    row=db.query(DetectionException).filter_by(id=exception_id,tenant_id=user.tenant_id).first()
    if not row:raise HTTPException(404,detail={"error_code":"DETECTION_EXCEPTION_INVALID","message":"Exception not found"})
    row.status="cancelled";db.commit()
    audit_service.record(db,action="detection_exception_cancelled",user=user,resource_type="detection_exception",resource_id=row.id)
    return row

@router.post("/maintenance-windows",status_code=201)
def create_maintenance(payload: MaintenanceCreate,db: Session=Depends(get_db),user: User=Depends(require_permission(Permission.DETECTIONS_MAINTENANCE_MANAGE))):
    start,end=ensure_utc(payload.starts_at),ensure_utc(payload.ends_at)
    if not payload.scope or start>=end or end-start>timedelta(hours=get_settings().DETECTION_MAINTENANCE_MAX_HOURS):
        raise HTTPException(422,detail={"error_code":"DETECTION_MAINTENANCE_CONFLICT","message":"Maintenance window is invalid"})
    row=DetectionMaintenanceWindow(tenant_id=user.tenant_id,created_by_id=user.id,**payload.model_dump())
    db.add(row);db.commit();db.refresh(row)
    audit_service.record(db,action="detection_maintenance_created",user=user,resource_type="detection_maintenance",resource_id=row.id,details={"starts_at":row.starts_at,"ends_at":row.ends_at})
    return row

@router.get("/maintenance-windows")
def maintenance(db: Session=Depends(get_db),user: User=Depends(require_permission(Permission.DETECTIONS_VIEW))):
    return db.query(DetectionMaintenanceWindow).filter_by(tenant_id=user.tenant_id).order_by(DetectionMaintenanceWindow.starts_at).limit(500).all()

@router.post("/maintenance-windows/{window_id}/cancel")
def cancel_maintenance(window_id: str,db: Session=Depends(get_db),user: User=Depends(require_permission(Permission.DETECTIONS_MAINTENANCE_MANAGE))):
    row=db.query(DetectionMaintenanceWindow).filter_by(id=window_id,tenant_id=user.tenant_id).first()
    if not row:raise HTTPException(404,detail={"error_code":"DETECTION_MAINTENANCE_CONFLICT","message":"Maintenance window not found"})
    row.status="cancelled";db.commit()
    audit_service.record(db,action="detection_maintenance_cancelled",user=user,resource_type="detection_maintenance",resource_id=row.id)
    return row

@router.get("/analytics")
def analytics(db: Session=Depends(get_db),user: User=Depends(require_permission(Permission.DETECTIONS_ANALYTICS_VIEW))):
    rules=db.query(DetectionRule).filter_by(tenant_id=user.tenant_id).all()
    matches=dict(db.query(DetectionMatch.rule_id,__import__("sqlalchemy").func.count(DetectionMatch.id)).filter(DetectionMatch.tenant_id==user.tenant_id).group_by(DetectionMatch.rule_id).all())
    result=[]
    for rule in rules:
        feedback=db.query(Feedback.id,Feedback.classification).join(Incident,Incident.id==Feedback.incident_id).join(Alert,Alert.incident_id==Incident.id).filter(
            Feedback.tenant_id==user.tenant_id,Alert.tenant_id==user.tenant_id,Alert.detection_rule_id==rule.id
        ).distinct().all()
        total_feedback=len(feedback)
        fp=sum(1 for _,value in feedback if value==Classification.FALSE_POSITIVE)
        tp=sum(1 for _,value in feedback if value==Classification.TRUE_POSITIVE)
        match_volume=matches.get(rule.id,0)
        recent=db.query(DetectionMatch).filter(
            DetectionMatch.tenant_id==user.tenant_id,DetectionMatch.rule_id==rule.id,
            DetectionMatch.triggered_at>=get_utc_now()-timedelta(hours=1)
        ).count()
        score=40+(20 if rule.production_version_id else 0)+(10 if rule.last_tested_at else 0)+(10 if match_volume else 0)
        if total_feedback:score-=round((fp/total_feedback)*30)
        recommendations=[]
        if not rule.production_version_id:recommendations.append("Validate, test, review, and publish a version")
        if recent>get_settings().DETECTION_NOISE_ALERTS_PER_HOUR:recommendations.append("Review noise volume and add a bounded suppression policy")
        if total_feedback and fp/total_feedback>=0.5:recommendations.append("Review false-positive examples and tune a new draft version")
        result.append({
            "rule_id":rule.id,"name":rule.name,"status":rule.lifecycle_status,"enabled":rule.enabled,
            "match_volume":match_volume,"alert_volume":db.query(Alert).filter_by(tenant_id=user.tenant_id,detection_rule_id=rule.id).count(),
            "true_positive_count":tp,"false_positive_count":fp,"feedback_count":total_feedback,
            "true_positive_rate":round(tp/total_feedback,4) if total_feedback else None,
            "false_positive_rate":round(fp/total_feedback,4) if total_feedback else None,
            "quality_score":max(0,min(100,score)),"recommendations":recommendations,
        })
    return {"rules":result,"missing_feedback_behavior":"Rates are null until analyst feedback exists."}

@router.post("/recommendations/{recommendation_id}/dismiss")
def dismiss_recommendation(recommendation_id: str,db: Session=Depends(get_db),user: User=Depends(require_permission(Permission.DETECTIONS_RECOMMENDATIONS_MANAGE))):
    row=db.query(DetectionRecommendation).filter_by(id=recommendation_id,tenant_id=user.tenant_id).first()
    if not row:raise HTTPException(404,detail={"error_code":"DETECTION_RULE_NOT_FOUND","message":"Recommendation not found"})
    row.status="dismissed";row.dismissed_by_id=user.id;row.dismissed_at=get_utc_now();db.commit()
    return row

@router.get("/mitre-coverage")
def coverage(db: Session=Depends(get_db),user: User=Depends(require_permission(Permission.DETECTIONS_ANALYTICS_VIEW))):
    result={}
    for rule in db.query(DetectionRule).filter_by(tenant_id=user.tenant_id).all():
        version=db.query(DetectionRuleVersion).filter_by(id=rule.current_version_id,tenant_id=user.tenant_id).first() if rule.current_version_id else None
        required=set(rule.data_source_requirements or (version.normalized_definition.get("data_sources",[]) if version else []))
        sources=db.query(DataSource).filter(DataSource.tenant_id==user.tenant_id,DataSource.source_key.in_(required)).all() if required else []
        healthy=not required or (required.issubset({source.source_key for source in sources}) and all(source.health_status=="healthy" for source in sources))
        has_true_positive=db.query(Feedback.id).join(Incident,Incident.id==Feedback.incident_id).join(Alert,Alert.incident_id==Incident.id).filter(
            Feedback.tenant_id==user.tenant_id,Feedback.classification==Classification.TRUE_POSITIVE,
            Alert.tenant_id==user.tenant_id,Alert.detection_rule_id==rule.id,
            Feedback.created_at>=get_utc_now()-timedelta(days=30)
        ).first() is not None
        for technique in rule.mitre_mappings or ([rule.mitre_technique_id] if rule.mitre_technique_id else []):
            item=result.setdefault(technique,{"technique_id":technique,"draft":0,"tested":0,"approved":0,"production":0,"healthy_source":0,"unhealthy_source":0,"recent_true_positive":0})
            if rule.production_version_id:
                item["production"]+=1;item["healthy_source" if healthy else "unhealthy_source"]+=1
                if has_true_positive:item["recent_true_positive"]+=1
            else:item["draft"]+=1
            if version and (version.test_result or {}).get("status")=="passed":item["tested"]+=1
            if version and version.lifecycle_status in {"approved","production","disabled"}:item["approved"]+=1
    return {"coverage":list(result.values()),"limitations":"Mappings indicate intended coverage, not proven telemetry or efficacy."}

@router.post("/content-packs/import")
def import_pack(payload: ContentPackRequest,db: Session=Depends(get_db),user: User=Depends(require_permission(Permission.DETECTIONS_CONTENT_PACK_MANAGE))):
    manifest=payload.manifest
    import hashlib,json
    if len(json.dumps(manifest,separators=(",",":"),default=str).encode())>get_settings().DETECTION_CONTENT_PACK_MAX_BYTES:
        raise HTTPException(413,detail={"error_code":"CONTENT_PACK_INVALID","message":"Content pack exceeds configured size"})
    required={"identifier","version","name","publisher","rules"}
    if not required.issubset(manifest) or not isinstance(manifest["rules"],list) or len(manifest["rules"])>get_settings().DETECTION_IMPORT_MAX_RULES:
        raise HTTPException(422,detail={"error_code":"CONTENT_PACK_INVALID","message":"Content pack manifest is invalid"})
    identities=[str(item.get("id") or item.get("name") or "") for item in manifest["rules"]]
    if any(not item for item in identities) or len(identities)!=len(set(identities)):
        raise HTTPException(409,detail={"error_code":"CONTENT_PACK_CONFLICT","message":"Content pack contains duplicate or missing rule identities"})
    reports=[detection_lifecycle_service.validate(item.get("definition") or {},sigma_content=item.get("sigma"),db=db) for item in manifest["rules"]]
    response={"valid":all(x["valid"] for x in reports),"rule_count":len(reports),"reports":reports,"installed":False}
    if payload.dry_run or not response["valid"]:return response
    checksum=hashlib.sha256(json.dumps(manifest,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    if db.query(DetectionContentPack).filter_by(tenant_id=user.tenant_id,identifier=manifest["identifier"],version=manifest["version"]).first():
        raise HTTPException(409,detail={"error_code":"CONTENT_PACK_CONFLICT","message":"Content pack version already exists"})
    row=DetectionContentPack(tenant_id=user.tenant_id,identifier=manifest["identifier"],version=manifest["version"],name=manifest["name"],publisher=manifest["publisher"],manifest=manifest,checksum=checksum,installed_by_id=user.id)
    db.add(row);db.flush()
    installed_rules=[]
    from src.models.sqlalchemy import RuleType,Severity
    for item in manifest["rules"]:
        definition=item.get("definition") or {}
        rule=DetectionRule(
            tenant_id=user.tenant_id,name=item.get("name") or "Imported detection",
            description=item.get("description"),type=RuleType.SIGMA if item.get("sigma") else RuleType.CUSTOM,
            rule_type=RuleType.SIGMA if item.get("sigma") else RuleType.CUSTOM,
            severity=Severity(str(item.get("severity") or "medium").lower()),
            enabled=False,detection_kind=definition.get("kind","event_match"),
            created_by=user.id,owner_id=user.id,lifecycle_status="draft",
            sigma_rule_id=str(definition.get("id")) if item.get("sigma") and definition.get("id") else None,
            protected=False,tags=item.get("tags") or [],mitre_mappings=definition.get("mitre_mappings") or [],
        )
        db.add(rule);db.flush()
        version=detection_lifecycle_service.create_version(db,rule,user.id,definition,original_content=item.get("sigma"),summary=f"Imported from {manifest['identifier']} {manifest['version']}")
        version.source_metadata={"content_pack_id":row.id,"publisher":manifest["publisher"]}
        installed_rules.append(rule.id)
    db.commit();response.update({"installed":True,"content_pack_id":row.id,"rule_ids":installed_rules})
    audit_service.record(db,action="detection_content_pack_imported",user=user,resource_type="detection_content_pack",resource_id=row.id,details={"identifier":row.identifier,"version":row.version,"checksum":row.checksum,"rule_count":len(installed_rules)})
    return response

@router.get("/content-packs")
def content_packs(db: Session=Depends(get_db),user: User=Depends(require_permission(Permission.DETECTIONS_CONTENT_PACKS_VIEW))):
    return db.query(DetectionContentPack).filter_by(tenant_id=user.tenant_id).order_by(DetectionContentPack.created_at.desc()).limit(200).all()

@router.get("/content-packs/{pack_id}/export")
def export_pack(pack_id: str,db: Session=Depends(get_db),user: User=Depends(require_permission(Permission.DETECTIONS_EXPORT))):
    row=db.query(DetectionContentPack).filter_by(id=pack_id,tenant_id=user.tenant_id).first()
    if not row:raise HTTPException(404,detail={"error_code":"CONTENT_PACK_INVALID","message":"Content pack not found"})
    return {"manifest":row.manifest,"checksum":row.checksum,"format":"socluma-json","safe_filename":f"{row.identifier}-{row.version}.json"}
