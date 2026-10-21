from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import yaml
from fastapi import HTTPException
from starlette.requests import Request

from src.core.config import Settings
from src.models.pydantic import ConnectorExecutionCreate, ResponseActionCreate
from src.services.response_action_service import UnsupportedResponseAction, response_action_service
from src.services.soar_action_service import soar_action_service


@pytest.mark.parametrize("policy,requested,expected", [
    (True, False, True), (True, None, True), (True, True, True),
    (False, True, True), (False, False, False), (False, None, False),
])
def test_execution_request_cannot_relax_connector_approval(policy, requested, expected):
    data = ConnectorExecutionCreate(connector_id="connector", action_name="notify", requires_approval=requested)
    assert soar_action_service._requires_approval(SimpleNamespace(requires_approval=policy), data) is expected


def test_connector_approval_roles_cannot_be_replaced_by_request():
    db = MagicMock()
    execution = SimpleNamespace(tenant_id="tenant", id="execution")
    connector = SimpleNamespace(requires_approval=True, approval_roles=["admin", "soc_manager"])
    data = ConnectorExecutionCreate(connector_id="connector", action_name="notify", approval_roles=["viewer"])
    soar_action_service._create_approvals(db, execution, connector, data, "requester")
    assert [call.args[0].required_role for call in db.add.call_args_list] == ["admin", "soc_manager"]


def test_legacy_response_action_does_not_create_false_success(monkeypatch):
    monkeypatch.setattr("src.services.response_action_service.incident_service.get_incident_model", lambda *args: object())
    db = MagicMock()
    data = ResponseActionCreate(action_type="block_ip", details={"ip": "192.0.2.1"})
    with pytest.raises(UnsupportedResponseAction, match="configured SOAR connector"):
        response_action_service.create_action(db, "tenant", "incident", "user", data)
    db.add.assert_not_called()
    db.commit.assert_not_called()


def test_legacy_response_endpoint_returns_explicit_unavailable(monkeypatch):
    from src.api.v1.incidents import create_response_action

    monkeypatch.setattr("src.services.response_action_service.incident_service.get_incident_model", lambda *args: object())
    with pytest.raises(HTTPException) as error:
        create_response_action("incident", ResponseActionCreate(action_type="block_ip"),
                               Request({"type": "http"}), MagicMock(),
                               SimpleNamespace(tenant_id="tenant", id="user"))
    assert error.value.status_code == 501
    assert error.value.detail["error_code"] == "RESPONSE_ACTION_EXECUTOR_UNAVAILABLE"


def test_failed_report_is_not_left_running(monkeypatch):
    from src.workers import tasks

    db = MagicMock()
    job = SimpleNamespace(status="running", error_code=None, completed_at=None)
    db.query.return_value.filter_by.return_value.first.return_value = job
    monkeypatch.setattr(tasks, "SessionLocal", lambda: db)
    monkeypatch.setattr(tasks.ioc_commercial_service, "process_report", MagicMock(side_effect=PermissionError("denied")))
    with pytest.raises(PermissionError):
        tasks.process_ioc_report.run("job", "tenant")
    assert job.status == "failed"
    assert job.error_code == "IOC_REPORT_GENERATION_FAILED"
    assert job.completed_at is not None
    db.rollback.assert_called_once()
    db.commit.assert_called_once()
    db.close.assert_called_once()


def test_missing_report_artifact_returns_safe_service_error(monkeypatch):
    from datetime import timedelta
    from src.api.v1.ioc_commercial import download_report
    from src.services.audit_management_service import LocalAuditArtifactStorage
    from src.utils.datetime_utils import get_utc_now

    db = MagicMock()
    job = SimpleNamespace(status="completed", artifact_key="missing", expires_at=get_utc_now() + timedelta(hours=1))
    db.query.return_value.filter_by.return_value.first.return_value = job
    monkeypatch.setattr(LocalAuditArtifactStorage, "__init__", lambda *args: None)
    monkeypatch.setattr(LocalAuditArtifactStorage, "read", MagicMock(side_effect=FileNotFoundError("private path")))
    with pytest.raises(HTTPException) as error:
        download_report("job", Request({"type": "http"}), db, SimpleNamespace(tenant_id="tenant"))
    assert error.value.status_code == 503
    assert "private path" not in str(error.value.detail)


def test_report_queue_failure_is_explicit_and_persisted(monkeypatch):
    from src.api.v1.ioc_commercial import create_report
    from src.workers import tasks

    db = MagicMock()
    job = SimpleNamespace(id="job", status="pending", error_code=None)
    monkeypatch.setattr(tasks.ioc_commercial_service, "create_report", lambda *args: job)
    monkeypatch.setattr(tasks.process_ioc_report, "delay", MagicMock(side_effect=ConnectionError("broker offline")))
    with pytest.raises(HTTPException) as error:
        create_report({"format": "json"}, Request({"type": "http"}), db,
                      SimpleNamespace(tenant_id="tenant"))
    assert error.value.status_code == 503
    assert job.status == "failed"
    assert job.error_code == "IOC_REPORT_QUEUE_UNAVAILABLE"
    db.rollback.assert_called_once()
    db.commit.assert_called_once()


def test_production_compose_environment_passes_runtime_validation():
    root = Path(__file__).resolve().parents[2]
    compose = yaml.safe_load((root / "docker/docker-compose.prod.yml").read_text())
    env = {}
    for entry in compose["services"]["backend"]["environment"]:
        key, value = entry.split("=", 1)
        if not value.startswith("${"):
            env[key] = value
    env.update(
        POSTGRES_USER="socluma", POSTGRES_DB="socluma", POSTGRES_PASSWORD="test-database-passphrase-2026",
        SECRET_KEY="s" * 48, JWT_SECRET_KEY="j" * 48, REFRESH_TOKEN_SECRET="r" * 48,
        COLLECTOR_TOKEN_SECRET="c" * 48, OPENAI_API_KEY="test-provider-key-not-used",
        FRONTEND_PUBLIC_URL="https://soc.example.com", ALLOWED_HOSTS=["soc.example.com"],
        BACKEND_CORS_ORIGINS=["https://soc.example.com"], DATABASE_URL_OVERRIDE=None,
    )
    Settings(_env_file=None, **env).validate_for_runtime()
    assert compose["services"]["worker"]["environment"] == compose["services"]["backend"]["environment"]


@pytest.mark.parametrize("filename,volume", [
    ("docker-compose.yml", "application_data"),
    ("docker-compose.prod.yml", "application_data"),
    ("docker-compose.acceptance.yml", "acceptance_application_data"),
])
def test_compose_shares_artifacts_and_runs_one_scheduler(filename, volume):
    root = Path(__file__).resolve().parents[2]
    compose = yaml.safe_load((root / "docker" / filename).read_text())
    for name in ("backend", "worker"):
        assert f"{volume}:/var/lib/socluma" in compose["services"][name]["volumes"]
    scheduler = compose["services"]["scheduler"]
    assert scheduler["extends"]["service"] == "worker"
    assert " beat " in scheduler["command"]
    assert "--schedule=/var/lib/socluma/" in scheduler["command"]
