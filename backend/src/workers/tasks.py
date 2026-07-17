import time

from billiard.exceptions import SoftTimeLimitExceeded

from src.core.database import SessionLocal
from src.core.logging import logger, request_id_ctx
from src.core.observability import WORKER_EXECUTION_TIME
from src.models.sqlalchemy import ActionExecutionStatus, Alert, ConnectorActionExecution
from src.services.incident_service import incident_service
from src.services.soar_action_service import soar_action_service

from .celery_app import celery_app


def process_alert_for_incident_sync(alert_id: str) -> str:
    db = SessionLocal()
    try:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if alert is None:
            raise ValueError("Alert not found")

        incident = incident_service.process_alert(db, alert)
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
