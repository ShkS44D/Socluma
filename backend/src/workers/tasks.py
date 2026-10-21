import time

from billiard.exceptions import SoftTimeLimitExceeded

from src.core.database import SessionLocal
from src.core.logging import logger, request_id_ctx
from src.core.observability import WORKER_EXECUTION_TIME
from datetime import timedelta

from src.models.sqlalchemy import (
    ActionExecutionStatus, Alert, ConnectorActionExecution, OrganizationMembership,
    OrganizationStatus, SavedSearch, ScheduledSearch, ScheduledSearchRun, SecurityEvent,
    TelemetryFailure, Tenant, User,
    DetectionRuleVersion, DetectionSimulationJob,
    IOC, IOCHuntJob, IOCImportJob, IOCBulkActionJob, IOCReportJob,
    ThreatSyncConfiguration, ThreatSyncJob,
)
from src.core.permissions import membership_permissions
from src.services.detection_engine import detection_engine
from src.utils.datetime_utils import get_utc_now
from src.services.entity_investigation_service import entity_investigation_service
from src.services.incident_service import incident_service
from src.services.soar_action_service import soar_action_service
from src.services.organization_service import organization_service
from src.services.account_security_service import account_security_service
from src.services.auth_service import auth_service
from src.services.audit_management_service import audit_management_service
from src.services.search_service import search_service
from src.services.detection_lifecycle_service import detection_lifecycle_service
from src.services.ioc_intelligence_service import ioc_intelligence_service
from src.services.ioc_commercial_service import IOCCommercialError, ioc_commercial_service
from src.services.audit_service import audit_service

from .celery_app import celery_app


@celery_app.task(name="process_threat_sync", bind=True, max_retries=3, retry_backoff=True, retry_jitter=True)
def process_threat_sync(self, job_id: str, tenant_id: str) -> dict:
    db = SessionLocal()
    try:
        job = ioc_commercial_service.process_sync(db, job_id, tenant_id)
        audit_service.record(
            db, action=f"{job.provider}_sync_{job.status}", tenant_id=tenant_id,
            actor_type="system", resource_type="threat_sync_job", resource_id=job.id,
            status="success" if job.status == "completed" else job.status,
            details={"counts": job.counts, "failure_code": job.failure_code},
        )
        if job.status == "failed" and self.request.retries < self.max_retries:
            raise self.retry(exc=RuntimeError("Threat synchronization failed"))
        return {"id": job.id, "status": job.status, "counts": job.counts}
    except Exception as exc:
        db.rollback()
        if self.request.retries < self.max_retries:
            raise self.retry(exc=RuntimeError("Threat synchronization failed"))
        return {"id": job_id, "status": "failed"}
    finally:
        db.close()


@celery_app.task(name="process_ioc_import", bind=True, max_retries=1)
def process_ioc_import(self, job_id: str, tenant_id: str) -> dict:
    db = SessionLocal()
    try:
        job = ioc_commercial_service.process_import(db, job_id, tenant_id)
        audit_service.record(
            db, action=f"ioc_import_{job.status}", tenant_id=tenant_id,
            actor_type="system", resource_type="ioc_import_job", resource_id=job.id,
            status="success" if job.status in {"completed", "validated"} else job.status,
            details={"counts": job.counts, "error_code": job.error_code},
        )
        return {"id": job.id, "status": job.status, "counts": job.counts}
    except Exception as exc:
        db.rollback()
        if self.request.retries < self.max_retries:
            raise self.retry(exc=RuntimeError("IOC import failed"), countdown=3)
        return {"id": job_id, "status": "failed"}
    finally:
        db.close()


@celery_app.task(name="process_ioc_bulk_action", bind=True, max_retries=1)
def process_ioc_bulk_action(self, job_id: str, tenant_id: str) -> dict:
    db = SessionLocal()
    try:
        job = ioc_commercial_service.process_bulk(db, job_id, tenant_id)
        audit_service.record(
            db, action=f"ioc_bulk_action_{job.status}", tenant_id=tenant_id,
            actor_type="system", resource_type="ioc_bulk_action_job", resource_id=job.id,
            details={"action": job.action, "result_count": len(job.results or [])},
        )
        return {"id": job.id, "status": job.status}
    finally:
        db.close()


@celery_app.task(name="process_ioc_report", bind=True, max_retries=1)
def process_ioc_report(self, job_id: str, tenant_id: str) -> dict:
    db = SessionLocal()
    try:
        job = ioc_commercial_service.process_report(db, job_id, tenant_id)
        audit_service.record(
            db, action="ioc_report_completed", tenant_id=tenant_id,
            actor_type="system", resource_type="ioc_report_job", resource_id=job.id,
            details={"format": job.format, "checksum": job.checksum, "manifest": job.manifest},
        )
        return {"id": job.id, "status": job.status}
    except Exception:
        db.rollback()
        job = db.query(IOCReportJob).filter_by(id=job_id, tenant_id=tenant_id).first()
        if job is not None:
            job.status = "failed"
            job.error_code = "IOC_REPORT_GENERATION_FAILED"
            job.completed_at = get_utc_now()
            db.commit()
        logger.exception("IOC report generation failed", extra={"job_id": job_id, "tenant_id": tenant_id})
        raise
    finally:
        db.close()


@celery_app.task(name="run_due_threat_syncs")
def run_due_threat_syncs() -> dict:
    db = SessionLocal()
    queued = 0
    try:
        now = get_utc_now()
        configs = db.query(ThreatSyncConfiguration).join(
            Tenant, Tenant.id == ThreatSyncConfiguration.tenant_id
        ).filter(
            ThreatSyncConfiguration.enabled.is_(True),
            ThreatSyncConfiguration.schedule_seconds.isnot(None),
            Tenant.status == OrganizationStatus.ACTIVE,
            (ThreatSyncConfiguration.next_run_at.is_(None)) | (ThreatSyncConfiguration.next_run_at <= now),
        ).limit(100).all()
        for config in configs:
            running = db.query(ThreatSyncJob.id).filter(
                ThreatSyncJob.tenant_id == config.tenant_id,
                ThreatSyncJob.configuration_id == config.id,
                ThreatSyncJob.status.in_(["pending", "running"]),
            ).first()
            config.next_run_at = now + timedelta(seconds=config.schedule_seconds)
            if running:
                continue
            job = ThreatSyncJob(
                tenant_id=config.tenant_id, configuration_id=config.id,
                provider=config.provider, direction="pull",
                counts={"imported": 0, "updated": 0, "duplicates": 0, "rejected": 0, "failed": 0, "unsupported": 0},
                failure_details={},
            )
            db.add(job)
            db.flush()
            process_threat_sync.delay(job.id, config.tenant_id)
            queued += 1
        db.commit()
        return {"queued": queued}
    finally:
        db.close()


@celery_app.task(name="cleanup_ioc_commercial_jobs")
def cleanup_ioc_commercial_jobs() -> dict:
    db = SessionLocal()
    try:
        result = ioc_commercial_service.cleanup_expired_artifacts(db)
        audit_service.record(
            db,
            action="ioc_commercial_retention_completed",
            actor_type="system",
            resource_type="ioc_commercial_retention",
            details=result,
        )
        return result
    finally:
        db.close()


@celery_app.task(name="run_ioc_hunt", bind=True, max_retries=2, soft_time_limit=300)
def run_ioc_hunt(self, job_id: str, tenant_id: str) -> dict:
    """Run a bounded tenant-scoped historical IOC hunt with exact provenance."""
    db = SessionLocal()
    try:
        job = db.query(IOCHuntJob).filter_by(id=job_id, tenant_id=tenant_id).first()
        if not job:
            return {"status": "not_found"}
        if job.cancellation_requested:
            job.status, job.completed_at = "cancelled", get_utc_now()
            db.commit()
            return {"status": "cancelled"}
        ioc = db.query(IOC).filter_by(id=job.ioc_id, tenant_id=tenant_id).first()
        if not ioc:
            job.status, job.error_code, job.completed_at = "failed", "IOC_NOT_FOUND", get_utc_now()
            db.commit()
            return {"status": "failed"}
        job.status, job.started_at = "running", get_utc_now()
        db.commit()
        since = get_utc_now() - timedelta(days=int(job.query.get("days", 30)))
        limit = int(job.query.get("event_limit", 10_000))
        events = db.query(SecurityEvent).filter(
            SecurityEvent.tenant_id == tenant_id, SecurityEvent.timestamp >= since,
        ).order_by(SecurityEvent.timestamp.desc()).limit(limit + 1).all()
        job.truncated = len(events) > limit
        events = events[:limit]
        matches = 0
        for index, event in enumerate(events):
            if index % 100 == 0:
                db.refresh(job)
                if job.cancellation_requested:
                    job.status, job.completed_at = "cancelled", get_utc_now()
                    db.commit()
                    return {"status": "cancelled"}
                job.progress = int((index / max(1, len(events))) * 100)
            before = ioc.internal_sighting_count or 0
            ioc_intelligence_service.match_event(db, event, ioc_id=ioc.id)
            matches += max(0, (ioc.internal_sighting_count or 0) - before)
        job.events_scanned, job.matches_found = len(events), matches
        job.progress, job.status, job.completed_at = 100, "completed", get_utc_now()
        db.commit()
        return {"status": "completed", "matches": matches, "truncated": job.truncated}
    except SoftTimeLimitExceeded:
        db.rollback()
        job = db.query(IOCHuntJob).filter_by(id=job_id, tenant_id=tenant_id).first()
        if job:
            job.status, job.error_code, job.completed_at = "failed", "IOC_HUNT_LIMIT_EXCEEDED", get_utc_now()
            db.commit()
        return {"status": "failed"}
    except Exception as exc:
        db.rollback()
        job = db.query(IOCHuntJob).filter_by(id=job_id, tenant_id=tenant_id).first()
        if job:
            job.status, job.error_code, job.completed_at = "failed", type(exc).__name__[:80], get_utc_now()
            db.commit()
        logger.exception("IOC hunt failed", extra={"tenant_id": tenant_id, "job_id": job_id})
        return {"status": "failed"}
    finally:
        db.close()


@celery_app.task(name="run_detection_simulation", bind=True)
def run_detection_simulation(self, job_id: str, tenant_id: str) -> dict:
    """Run a bounded, read-only historical simulation in explicit tenant context."""
    db = SessionLocal()
    try:
        job = db.query(DetectionSimulationJob).filter_by(id=job_id, tenant_id=tenant_id).first()
        if not job or job.cancel_requested:
            return {"status": "cancelled" if job else "not_found"}
        version = db.query(DetectionRuleVersion).filter_by(
            id=job.version_id, tenant_id=tenant_id
        ).first()
        if not version:
            job.status, job.error, job.completed_at = "failed", "DETECTION_VERSION_NOT_FOUND", get_utc_now()
            db.commit()
            return {"status": "failed"}
        job.status = "running"
        db.commit()
        events = db.query(SecurityEvent).filter(
            SecurityEvent.tenant_id == tenant_id,
            SecurityEvent.timestamp >= job.time_start,
            SecurityEvent.timestamp <= job.time_end,
        ).order_by(SecurityEvent.timestamp).limit(job.event_limit).all()
        if job.cancel_requested:
            job.status, job.completed_at = "cancelled", get_utc_now()
        else:
            job.result = detection_lifecycle_service.evaluate_events(
                version.normalized_definition, events
            )
            job.events_scanned = job.result["events_scanned"]
            job.matches = job.result["matches"]
            job.status, job.completed_at = "completed", get_utc_now()
        db.commit()
        return {"status": job.status, "job_id": job.id}
    except SoftTimeLimitExceeded:
        job = db.query(DetectionSimulationJob).filter_by(id=job_id, tenant_id=tenant_id).first()
        if job:
            job.status, job.error, job.completed_at = "failed", "DETECTION_SIMULATION_RUNTIME_EXCEEDED", get_utc_now()
            db.commit()
        return {"status": "failed"}
    except Exception as exc:
        db.rollback()
        job = db.query(DetectionSimulationJob).filter_by(id=job_id, tenant_id=tenant_id).first()
        if job:
            job.status, job.error, job.completed_at = "failed", type(exc).__name__, get_utc_now()
            db.commit()
        logger.exception("Detection simulation failed", extra={"tenant_id": tenant_id, "job_id": job_id})
        return {"status": "failed"}
    finally:
        db.close()


@celery_app.task(name="run_due_scheduled_searches")
def run_due_scheduled_searches() -> dict:
    """Execute due schedules with fresh owner, membership, tenant, and permission checks."""
    db, now, completed, disabled, failed = SessionLocal(), get_utc_now(), 0, 0, 0
    try:
        schedules = db.query(ScheduledSearch).filter(
            ScheduledSearch.status == "active", ScheduledSearch.next_run_at <= now,
        ).limit(100).all()
        for schedule in schedules:
            run = ScheduledSearchRun(
                tenant_id=schedule.tenant_id, schedule_id=schedule.id, status="running",
            )
            db.add(run); db.flush()
            try:
                owner = db.query(User).filter_by(id=schedule.owner_id, tenant_id=schedule.tenant_id, is_active=True).first()
                membership = db.query(OrganizationMembership).filter_by(
                    tenant_id=schedule.tenant_id, user_id=schedule.owner_id, is_active=True,
                ).first()
                tenant = db.query(Tenant).filter_by(id=schedule.tenant_id, status=OrganizationStatus.ACTIVE).first()
                saved = db.query(SavedSearch).filter_by(id=schedule.saved_search_id, tenant_id=schedule.tenant_id).first()
                if not owner or not membership or not tenant or not saved:
                    schedule.status, schedule.failure_reason, run.status = "disabled", "Owner or organization is no longer eligible", "disabled"
                    disabled += 1
                else:
                    result = search_service.execute(
                        db, tenant_id=tenant.id, user_id=owner.id,
                        permission_values=membership_permissions(db, owner),
                        query_text=saved.display_query, resource_scope=saved.resource_scope,
                        start=None, end=None, page=1, page_size=1,
                        sort_field=(saved.sort or {}).get("field", "timestamp"),
                        sort_direction=(saved.sort or {}).get("direction", "desc"),
                        record_history=False,
                    )
                    run.status, run.result_count, run.execution_time_ms = "completed", result["total_count"], result["execution_time_ms"]
                    schedule.last_result_count, schedule.failure_reason = result["total_count"], None
                    completed += 1
                delta = {"hourly": timedelta(hours=1), "daily": timedelta(days=1), "weekly": timedelta(days=7)}[schedule.cadence]
                schedule.last_run_at, schedule.next_run_at = now, now + delta
                run.completed_at = get_utc_now()
            except Exception as exc:
                run.status, run.failure_reason, run.completed_at = "failed", type(exc).__name__, get_utc_now()
                schedule.failure_reason = type(exc).__name__
                failed += 1
            db.commit()
        return {"completed": completed, "disabled": disabled, "failed": failed}
    finally:
        db.close()


@celery_app.task(
    name="process_ingested_event",
    bind=True,
    autoretry_for=(RuntimeError,),
    retry_backoff=True,
    retry_jitter=True,
    max_retries=5,
)
def process_ingested_event(self, event_id: str) -> str:
    """Run downstream detection after the accepted event transaction commits."""
    db = SessionLocal()
    try:
        event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
        if event is None:
            return f"missing:{event_id}"
        if event.processing_status == "processed":
            return event_id
        entity_investigation_service.extract_event(db, event)
        # IOC matching is tenant-scoped and runs after durable ingestion. The
        # service uses a bounded database fallback, so Redis outages cannot
        # silently disable matching.
        sightings = ioc_intelligence_service.match_event(db, event)
        for ioc_id in {sighting.ioc_id for sighting in sightings}:
            matched_ioc = db.query(IOC).filter_by(id=ioc_id, tenant_id=event.tenant_id).first()
            if matched_ioc:
                ioc_commercial_service.notification_allowed(
                    db,
                    event.tenant_id,
                    "ioc_sighting",
                    matched_ioc.id,
                    matched_ioc.tlp,
                )
        detection_engine.analyze_and_process_event(db, event.tenant_id, event)
        event.processing_status = "processed"
        event.processed_at = get_utc_now()
        db.commit()
        return event_id
    except Exception as exc:
        db.rollback()
        event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
        if event:
            event.processing_status = "retry" if self.request.retries < self.max_retries else "dead_letter"
            failure = TelemetryFailure(
                tenant_id=event.tenant_id,
                collector_id=event.collector_id,
                data_source_id=event.data_source_id,
                event_id=event.id,
                batch_id=event.batch_id,
                stage="detection",
                error_code=type(exc).__name__[:80],
                safe_error="Downstream event processing failed",
                payload={"event_id": event.id},
                state="retry" if self.request.retries < self.max_retries else "dead_letter",
                attempts=self.request.retries + 1,
                last_attempt_at=get_utc_now(),
            )
            db.add(failure)
            db.commit()
        raise RuntimeError("downstream processing failed") from exc
    finally:
        db.close()


def process_alert_for_incident_sync(alert_id: str, *, allow_external_enrichment: bool = True) -> str:
    db = SessionLocal()
    try:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if alert is None:
            raise ValueError("Alert not found")

        incident = incident_service.process_alert(db, alert, allow_external_enrichment=allow_external_enrichment)
        if incident is None:
            logger.info("Alert %s retained pending correlation", alert_id)
            return f"pending:{alert_id}"
        logger.info("Processed alert %s into incident %s", alert_id, incident.id)
        return incident.id
    except Exception:
        db.rollback()
        logger.exception("Alert incident worker transaction rolled back", extra={"alert_id": alert_id})
        raise
    finally:
        db.close()


@celery_app.task(name="process_alert_for_incident", bind=True)
def process_alert_for_incident(self, alert_id: str) -> str:
    started = time.perf_counter()
    token = request_id_ctx.set(getattr(self.request, "id", None))
    try:
        incident_id = process_alert_for_incident_sync(alert_id)
        WORKER_EXECUTION_TIME.labels("process_alert_for_incident", "success").observe(time.perf_counter() - started)
        return incident_id
    except SoftTimeLimitExceeded:
        WORKER_EXECUTION_TIME.labels("process_alert_for_incident", "timeout").observe(time.perf_counter() - started)
        logger.exception("Worker timed out while processing alert into incident", extra={"alert_id": alert_id})
        return f"timeout:{alert_id}"
    except Exception:
        WORKER_EXECUTION_TIME.labels("process_alert_for_incident", "error").observe(time.perf_counter() - started)
        logger.exception("Worker failed to process alert into incident", extra={"alert_id": alert_id})
        return f"failed:{alert_id}"
    finally:
        request_id_ctx.reset(token)


def execute_connector_action_sync(execution_id: str, worker_id: str | None = None) -> str:
    db = SessionLocal()
    try:
        execution = soar_action_service.execute_pending(db, execution_id, worker_id=worker_id)
        logger.info("Executed SOAR action %s with status %s", execution.id, execution.status.value)
        return execution.id
    except SoftTimeLimitExceeded:
        execution = db.query(ConnectorActionExecution).filter(ConnectorActionExecution.id == execution_id).first()
        if execution and execution.status not in {
            ActionExecutionStatus.COMPLETED,
            ActionExecutionStatus.FAILED,
            ActionExecutionStatus.CANCELLED,
        }:
            execution.status = ActionExecutionStatus.FAILED
            execution.error = "Worker task timed out"
            execution.completed_at = soar_action_service._utcnow()
            soar_action_service._log(db, execution, "error", "SOAR action worker timed out")
            db.commit()
        logger.exception("SOAR connector worker timed out", extra={"execution_id": execution_id})
        raise
    except Exception:
        db.rollback()
        logger.exception("SOAR connector worker transaction rolled back", extra={"execution_id": execution_id})
        raise
    finally:
        db.close()


@celery_app.task(name="execute_connector_action", bind=True)
def execute_connector_action(self, execution_id: str) -> str:
    started = time.perf_counter()
    worker_id = getattr(self.request, "hostname", None) or getattr(self.request, "id", None)
    token = request_id_ctx.set(getattr(self.request, "id", None))
    try:
        result = execute_connector_action_sync(execution_id, worker_id=worker_id)
        WORKER_EXECUTION_TIME.labels("execute_connector_action", "success").observe(time.perf_counter() - started)
        return result
    except SoftTimeLimitExceeded:
        WORKER_EXECUTION_TIME.labels("execute_connector_action", "timeout").observe(time.perf_counter() - started)
        logger.exception("Worker timed out while executing SOAR connector action", extra={"execution_id": execution_id})
        return f"timeout:{execution_id}"
    except Exception:
        WORKER_EXECUTION_TIME.labels("execute_connector_action", "error").observe(time.perf_counter() - started)
        logger.exception("Worker failed to execute SOAR connector action", extra={"execution_id": execution_id})
        return f"failed:{execution_id}"
    finally:
        request_id_ctx.reset(token)


def purge_due_organizations_sync(limit: int = 100) -> list[str]:
    db = SessionLocal()
    try:
        return organization_service.purge_due_organizations(db, limit=limit)
    except Exception:
        db.rollback()
        logger.exception("Scheduled organization purge transaction rolled back")
        raise
    finally:
        db.close()


@celery_app.task(name="purge_due_organizations")
def purge_due_organizations(limit: int = 100) -> list[str]:
    """Safe manual/eager task path; scheduling is intentionally external."""
    return purge_due_organizations_sync(limit=limit)


def cleanup_authentication_records_sync() -> dict[str, int]:
    db = SessionLocal()
    try:
        return {
            "tokens_and_challenges": account_security_service.cleanup(db),
            "sessions": auth_service.cleanup_expired_sessions(db),
        }
    except Exception:
        db.rollback()
        logger.exception("Authentication-record cleanup transaction rolled back")
        raise
    finally:
        db.close()


@celery_app.task(name="cleanup_authentication_records")
def cleanup_authentication_records() -> dict[str, int]:
    """Idempotent cleanup path intended for an external daily schedule."""
    return cleanup_authentication_records_sync()


def process_audit_retention_sync(tenant_id: str, requested_by_id: str | None = None) -> str:
    db = SessionLocal()
    try:
        return audit_management_service.run_retention(
            db, tenant_id, requested_by_id=requested_by_id
        ).id
    except Exception:
        db.rollback()
        logger.exception("Audit retention job failed", extra={"tenant_id": tenant_id})
        raise
    finally:
        db.close()


@celery_app.task(name="process_audit_retention")
def process_audit_retention(tenant_id: str, requested_by_id: str | None = None) -> str:
    """Bounded tenant-scoped retention processing; schedule externally or with existing Celery Beat."""
    return process_audit_retention_sync(tenant_id, requested_by_id)


def process_audit_export_sync(job_id: str) -> str:
    db = SessionLocal()
    try:
        job = audit_management_service.process_export(db, job_id)
        return job.id
    except Exception:
        db.rollback()
        logger.exception("Audit export job failed", extra={"job_id": job_id})
        raise
    finally:
        db.close()


@celery_app.task(name="process_audit_export")
def process_audit_export(job_id: str) -> str:
    return process_audit_export_sync(job_id)


@celery_app.task(name="expire_audit_exports")
def expire_audit_exports() -> int:
    db = SessionLocal()
    try:
        return audit_management_service.expire_exports(db)
    finally:
        db.close()
