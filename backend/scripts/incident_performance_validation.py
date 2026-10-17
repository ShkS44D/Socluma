from __future__ import annotations

import argparse
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import statistics
import sys
import tempfile
import threading
import time
import tracemalloc
from typing import Any
import uuid

try:
    import psutil
except ImportError:  # Optional measurement dependency.
    psutil = None

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker

from src.api.deps import get_current_user, get_db
from src.core.database import Base
from src.core.security import create_access_token
from src.main import app
from src.models.sqlalchemy import (
    AIInvestigationConversation,
    AIInvestigationMessage,
    Alert,
    AlertSource,
    AlertSourceType,
    DetectionRule,
    EvidenceType,
    EventType,
    IOC,
    Incident,
    IncidentAlert,
    IncidentEntity,
    IncidentEvidence,
    IncidentIOC,
    IndicatorType,
    OrganizationMembership,
    OrganizationRole,
    SecurityEvent,
    Severity,
    Tenant,
    User,
    UserRole,
)
from src.services.ai_investigation_service import IncidentCopilotTools
from src.services.ai_investigation_service import ai_investigation_service
from src.services import ai_investigation_service as ai_module
from src.services.llm_provider import ProviderResult


def percentile(values: list[float], percentage: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * percentage))))
    return ordered[index]


@contextmanager
def validation_database(database_url: str | None):
    if not database_url:
        handle, database_path = tempfile.mkstemp(prefix="socluma-batch63-", suffix=".db")
        os.close(handle)
        engine = create_engine(f"sqlite:///{database_path}", connect_args={"check_same_thread": False})
        target = {"dialect": "sqlite", "host": "local", "database": database_path, "schema": None}
        print(f"Validation target: SQLite {database_path}", file=sys.stderr)
        try:
            yield engine, target
        finally:
            engine.dispose()
            Path(database_path).unlink(missing_ok=True)
        return

    url = make_url(database_url)
    if not url.drivername.startswith("postgresql"):
        raise ValueError("--database-url must use PostgreSQL for external validation")
    database_name = url.database or ""
    safe_markers = ("test", "validation", "batch", "perf", "rc", "ci")
    if not any(marker in database_name.lower() for marker in safe_markers):
        raise ValueError(
            "Refusing to run against a database without an explicit test marker "
            "(test, validation, batch, perf, rc, or ci) in its name"
        )
    schema_name = f"batch63_{uuid.uuid4().hex[:12]}"
    admin_engine = create_engine(url, pool_pre_ping=True)
    with admin_engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema_name}"'))
    engine = create_engine(
        url,
        pool_size=20,
        max_overflow=10,
        pool_timeout=30,
        pool_pre_ping=True,
        connect_args={"options": f"-csearch_path={schema_name}"},
    )
    target = {
        "dialect": "postgresql",
        "host": url.host or "local",
        "port": url.port or 5432,
        "database": database_name,
        "schema": schema_name,
    }
    print(
        f"Validation target: PostgreSQL host={target['host']} port={target['port']} "
        f"database={database_name} schema={schema_name}",
        file=sys.stderr,
    )
    try:
        yield engine, target
    finally:
        engine.dispose()
        try:
            with admin_engine.begin() as connection:
                connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema_name}" CASCADE'))
        finally:
            admin_engine.dispose()


def seed_dataset(Session, run_id: str) -> dict[str, Any]:
    db = Session()
    now = datetime.now(timezone.utc)
    tenants: list[dict[str, Any]] = []
    try:
        for tenant_number in range(2):
            tenant = Tenant(
                name=f"Performance Tenant {tenant_number}",
                slug=f"batch63-perf-{run_id}-{tenant_number}",
            )
            db.add(tenant)
            db.flush()
            users = []
            for user_number in range(2):
                user = User(
                    tenant_id=tenant.id,
                    email=f"perf-{run_id}-{tenant_number}-{user_number}@example.com",
                    hashed_password="not-used",
                    full_name=f"Performance Analyst {user_number}",
                    role=UserRole.ADMIN,
                )
                db.add(user)
                db.flush()
                db.add(OrganizationMembership(
                    tenant_id=tenant.id,
                    user_id=user.id,
                    role=OrganizationRole.ADMINISTRATOR,
                    is_active=True,
                ))
                users.append(user)
            source = AlertSource(
                tenant_id=tenant.id,
                name="Performance EDR",
                type=AlertSourceType.API,
                is_active=True,
            )
            rule = DetectionRule(
                tenant_id=tenant.id,
                name="High Volume PowerShell",
                event_type=EventType.PROCESS,
                severity=Severity.HIGH,
                condition={"Image|endswith": "powershell.exe"},
                created_by=users[0].id,
            )
            db.add_all([source, rule])
            db.flush()
            incident = Incident(
                tenant_id=tenant.id,
                title=f"Controlled high-volume incident {tenant_number}",
                description="Performance validation incident",
                severity=Severity.HIGH,
                risk_score=78,
                creation_source="detection_engine" if tenant_number == 0 else "correlation_engine",
                provenance_status="recorded",
                creation_reason="Primary PowerShell alert created incident",
                correlation_rule_name="Host and time window",
                correlation_key=f"host:perf-{tenant_number}",
                correlation_score=85,
                first_seen_at=now - timedelta(hours=2),
                last_seen_at=now,
                risk_score_breakdown={"base_severity": 30, "multiple_alerts": 10, "suspicious_behavior": 20, "threat_intelligence": 8, "mitre_techniques": 10, "total": 78},
                attack_technique={"technique_id": "T1059.001", "name": "PowerShell"},
            )
            db.add(incident)
            db.flush()
            alert_count = 100 if tenant_number == 0 else 20
            for sequence in range(alert_count):
                observed = now - timedelta(minutes=alert_count - sequence)
                raw = {
                    "Image": "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
                    "CommandLine": f"powershell.exe -EncodedCommand payload-{sequence}-" + "X" * 1200,
                    "Computer": f"perf-{tenant_number}",
                    "User": "PERF\\analyst",
                    "DestinationIp": f"198.51.100.{sequence % 200 + 1}",
                    "diagnostic": "Y" * 1000,
                }
                source_event = SecurityEvent(
                    tenant_id=tenant.id,
                    source="windows-edr",
                    event_type=EventType.PROCESS,
                    raw_event=raw,
                    normalized_event={
                        "process": "powershell.exe",
                        "command_line": raw["CommandLine"],
                        "host": f"perf-{tenant_number}",
                        "user": "analyst",
                        "destination_ip": raw["DestinationIp"],
                    },
                    severity=Severity.HIGH,
                    timestamp=observed,
                    processed=True,
                )
                db.add(source_event)
                db.flush()
                alert = Alert(
                    tenant_id=tenant.id,
                    source_id=source.id,
                    detection_rule_id=rule.id,
                    event_id=source_event.id,
                    ocsf_data={"class_name": "Process Activity", "activity_name": "Process launched", "raw_copy": raw},
                    raw_data=raw,
                    risk_score=70 + sequence % 20,
                    severity=Severity.HIGH,
                    matched_condition=json.dumps({"Image|endswith": "powershell.exe"}),
                    why_matched="PowerShell process matched encoded-command detection",
                )
                db.add(alert)
                db.flush()
                db.add(IncidentAlert(
                    incident_id=incident.id,
                    alert_id=alert.id,
                    correlation_score=85,
                    is_primary=sequence == 0,
                    attachment_reason="Primary detection" if sequence == 0 else "Shared host within 15 minutes",
                    correlation_reason="Primary alert created incident" if sequence == 0 else "Shared host within 15 minutes",
                    sequence_order=sequence,
                    risk_contribution=round(78 / alert_count, 4),
                    matching_entities=[{"type": "host", "value": f"perf-{tenant_number}"}],
                    matching_indicators=[],
                    time_delta_seconds=sequence * 60,
                ))
                if sequence == 0:
                    incident.primary_alert_id = alert.id
                if sequence < 30:
                    db.add(IncidentEntity(
                        tenant_id=tenant.id,
                        incident_id=incident.id,
                        entity_type="ip_address",
                        value=raw["DestinationIp"],
                        normalized_value=raw["DestinationIp"],
                        role="destination",
                        source_event_id=source_event.id,
                        source_alert_id=alert.id,
                        confidence=0.9,
                        risk_contribution=2,
                    ))
                    db.add(IncidentEvidence(
                        incident_id=incident.id,
                        tenant_id=tenant.id,
                        user_id=users[0].id,
                        source_event_id=source_event.id,
                        source_alert_id=alert.id,
                        type=EvidenceType.IP,
                        value=raw["DestinationIp"],
                        description="Observed destination",
                        confidence=0.8,
                        risk_contribution=1,
                    ))
            for ioc_number in range(5):
                ioc = IOC(
                    tenant_id=tenant.id,
                    type=IndicatorType.IP,
                    value=f"203.0.{tenant_number}.{ioc_number + 1}",
                    description="Controlled IOC",
                    severity=Severity.HIGH,
                    confidence_score=80,
                    created_by=users[0].id,
                )
                db.add(ioc)
                db.flush()
                db.add(IncidentIOC(tenant_id=tenant.id, incident_id=incident.id, ioc_id=ioc.id))
            for conversation_number in range(5):
                conversation = AIInvestigationConversation(
                    tenant_id=tenant.id,
                    incident_id=incident.id,
                    user_id=users[0].id,
                    title=f"Conversation {conversation_number}",
                )
                db.add(conversation)
                db.flush()
                for message_number in range(10):
                    db.add(AIInvestigationMessage(
                        tenant_id=tenant.id,
                        conversation_id=conversation.id,
                        role="user" if message_number % 2 == 0 else "assistant",
                        content=("Question" if message_number % 2 == 0 else "Grounded response") + f" {message_number} " + "Z" * 500,
                        message_metadata={"evidence_references": []},
                    ))
            tenants.append({
                "tenant_id": tenant.id,
                "incident_id": incident.id,
                "user_ids": [user.id for user in users],
            })
        provenance = (
            ("manual", "manual"),
            ("legacy_import", "legacy_derived"),
            ("playbook", "recorded"),
        )
        for number in range(98):
            tenant = tenants[number % 2]
            source, status = provenance[number] if number < len(provenance) else ("detection_engine", "recorded")
            db.add(Incident(
                tenant_id=tenant["tenant_id"],
                title=f"Additional incident {number}",
                description="Controlled incident",
                severity=Severity.MEDIUM,
                risk_score=40,
                creation_source=source,
                provenance_status=status,
            ))
        db.commit()
        return {
            "tenants": tenants,
            "incidents": 100,
            "alerts": 120,
            "events": 120,
            "entities": 50,
            "evidence": 50,
            "conversations": 10,
            "messages": 100,
            "iocs": 10,
            "users": 4,
            "provenance": ["manual", "legacy_derived", "playbook", "detection_engine", "correlation_engine"],
        }
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def measure_request(client: TestClient, path: str, headers: dict[str, str], query_counter: dict[str, int], repetitions: int = 5) -> dict[str, Any]:
    client.get(path, headers=headers)
    latencies: list[float] = []
    sizes: list[int] = []
    queries: list[int] = []
    for _ in range(repetitions):
        query_counter["count"] = 0
        started = time.perf_counter()
        response = client.get(path, headers=headers)
        latencies.append((time.perf_counter() - started) * 1000)
        sizes.append(len(response.content))
        queries.append(query_counter["count"])
        if response.status_code != 200:
            raise RuntimeError(f"{path} returned {response.status_code}: {response.text[:500]}")
    return {
        "median_ms": round(statistics.median(latencies), 2),
        "p95_ms": round(percentile(latencies, 0.95), 2),
        "queries": statistics.median(queries),
        "bytes": int(statistics.median(sizes)),
    }


def verify_copilot_idempotency(
    client: TestClient,
    Session,
    dataset: dict[str, Any],
    tenant_contexts: list[dict[str, Any]],
    concurrency: int,
    *,
    redis_available: bool,
) -> dict[str, Any]:
    primary = tenant_contexts[0]
    callers = max(2, min(concurrency, 16))
    request_id = f"batch63-idempotency-{'redis' if redis_available else 'local'}-{uuid.uuid4().hex}"
    question = "What evidence supports this incident?"
    headers = {**primary["headers"], "X-Request-ID": request_id}
    original_provider = ai_module.llm_provider.generate_copilot
    original_redis_from_url = ai_module.redis.from_url
    provider_attempts = 0
    provider_guard = threading.Lock()

    def controlled_fallback(*_args, **_kwargs):
        nonlocal provider_attempts
        with provider_guard:
            provider_attempts += 1
        time.sleep(0.2)
        return ProviderResult(error_category="timeout")

    if not redis_available:
        def unavailable_redis(*_args, **_kwargs):
            raise ai_module.redis.exceptions.ConnectionError("Controlled Redis outage")

        ai_module.redis.from_url = unavailable_redis
    ai_module.llm_provider.generate_copilot = controlled_fallback
    try:
        with ThreadPoolExecutor(max_workers=callers) as executor:
            futures = [
                executor.submit(
                    client.post,
                    f"/api/v1/ai/incident/{primary['incident_id']}/chat",
                    headers=headers,
                    json={"message": question},
                )
                for _ in range(callers)
            ]
            initial_responses = [future.result() for future in as_completed(futures)]
        completed = next((response for response in initial_responses if response.status_code == 200), None)
        if completed is None:
            raise RuntimeError(
                f"No idempotent Socluma Copilot caller completed: {[item.status_code for item in initial_responses]}"
            )
        completed_body = completed.json()
        attempts_after_initial = provider_attempts
        replay_responses = [
            client.post(
                f"/api/v1/ai/incident/{primary['incident_id']}/chat",
                headers=headers,
                json={"message": question},
            )
            for _ in range(callers)
        ]
        replay_bodies = [response.json() for response in replay_responses if response.status_code == 200]
        different_question = client.post(
            f"/api/v1/ai/incident/{primary['incident_id']}/chat",
            headers=headers,
            json={"message": "Use this request ID for a different question"},
        )
        conversation_id = completed_body["conversation_id"]
        other_user_read = client.get(
            f"/api/v1/ai/incident/{primary['incident_id']}/conversations/{conversation_id}",
            headers=tenant_contexts[1]["headers"],
        )
        cross_tenant_read = client.get(
            f"/api/v1/ai/incident/{primary['incident_id']}/conversations/{conversation_id}",
            headers=tenant_contexts[2]["headers"],
        )
        validation_db = Session()
        try:
            other_incident = validation_db.query(Incident).filter(
                Incident.tenant_id == dataset["tenants"][0]["tenant_id"],
                Incident.id != primary["incident_id"],
            ).first()
            messages = validation_db.query(AIInvestigationMessage).filter(
                AIInvestigationMessage.conversation_id == conversation_id,
            ).all()
            request_messages = [
                message for message in messages
                if (message.message_metadata or {}).get("request_id") == request_id
            ]
        finally:
            validation_db.close()
        other_incident_read = client.get(
            f"/api/v1/ai/incident/{other_incident.id}/conversations/{conversation_id}",
            headers=primary["headers"],
        )

        failed_request_id = f"{request_id}-failure"
        failed_headers = {**primary["headers"], "X-Request-ID": failed_request_id}

        def interrupted_provider(*_args, **_kwargs):
            raise TimeoutError("Controlled provider interruption")

        ai_module.llm_provider.generate_copilot = interrupted_provider
        interrupted = client.post(
            f"/api/v1/ai/incident/{primary['incident_id']}/chat",
            headers=failed_headers,
            json={"message": question},
        )
        ai_module.llm_provider.generate_copilot = controlled_fallback
        retry_after_interruption = client.post(
            f"/api/v1/ai/incident/{primary['incident_id']}/chat",
            headers=failed_headers,
            json={"message": question},
        )
        validation_db = Session()
        try:
            failed_request_messages = validation_db.query(AIInvestigationMessage).filter(
                AIInvestigationMessage.tenant_id == dataset["tenants"][0]["tenant_id"],
            ).all()
            failed_request_roles = [
                message.role for message in failed_request_messages
                if (message.message_metadata or {}).get("request_id") == failed_request_id
            ]
        finally:
            validation_db.close()

        return {
            "mode": "redis" if redis_available else "local_fallback",
            "callers": callers,
            "initial_statuses": sorted(response.status_code for response in initial_responses),
            "provider_attempts_for_duplicate_scope": attempts_after_initial,
            "replay_statuses": sorted(response.status_code for response in replay_responses),
            "replays_match": bool(replay_bodies) and all(
                body["conversation_id"] == conversation_id and body["answer"] == completed_body["answer"]
                for body in replay_bodies
            ),
            "request_message_roles": sorted(message.role for message in request_messages),
            "different_question_status": different_question.status_code,
            "other_user_read_status": other_user_read.status_code,
            "cross_tenant_read_status": cross_tenant_read.status_code,
            "other_incident_read_status": other_incident_read.status_code,
            "interrupted_status": interrupted.status_code,
            "retry_after_interruption_status": retry_after_interruption.status_code,
            "interrupted_request_roles_after_retry": sorted(failed_request_roles),
            "local_locks_remaining": len(ai_investigation_service._local_request_locks),
        }
    finally:
        ai_module.llm_provider.generate_copilot = original_provider
        ai_module.redis.from_url = original_redis_from_url


def _run_with_engine(
    concurrency: int,
    requests_count: int,
    engine,
    target: dict[str, Any],
) -> dict[str, Any]:
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    pool_stats = {"checkouts": 0, "checkins": 0, "active": 0, "max_active": 0}
    pool_guard = threading.Lock()

    @event.listens_for(engine, "checkout")
    def _checkout(*_args):
        with pool_guard:
            pool_stats["checkouts"] += 1
            pool_stats["active"] += 1
            pool_stats["max_active"] = max(pool_stats["max_active"], pool_stats["active"])

    @event.listens_for(engine, "checkin")
    def _checkin(*_args):
        with pool_guard:
            pool_stats["checkins"] += 1
            pool_stats["active"] = max(0, pool_stats["active"] - 1)

    Base.metadata.create_all(engine)
    run_id = uuid.uuid4().hex[:10]
    dataset = seed_dataset(Session, run_id)
    with engine.connect() as connection:
        database_version = connection.execute(
            text("SELECT version()") if target["dialect"] == "postgresql" else text("SELECT sqlite_version()")
        ).scalar_one()

    def override_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    def override_current_user():
        db = Session()
        try:
            return db.query(User).filter(User.id == dataset["tenants"][0]["user_ids"][0]).one()
        finally:
            db.close()

    app.dependency_overrides[get_current_user] = override_current_user
    client = TestClient(app, raise_server_exceptions=False)
    query_counter = {"count": 0}
    event.listen(engine, "before_cursor_execute", lambda *args, **kwargs: query_counter.__setitem__("count", query_counter["count"] + 1))
    tenant_contexts = []
    for tenant in dataset["tenants"]:
        for user_id in tenant["user_ids"]:
            tenant_contexts.append({
                "incident_id": tenant["incident_id"],
                "headers": {"Authorization": f"Bearer {create_access_token({'sub': user_id})}"},
            })
    primary = tenant_contexts[0]
    results = {
        "database_target": target,
        "database_version": database_version,
        "dataset": {key: value for key, value in dataset.items() if key != "tenants"},
        "incident_detail": measure_request(client, f"/api/v1/incidents/{primary['incident_id']}", primary["headers"], query_counter),
        "explanation": measure_request(client, f"/api/v1/incidents/{primary['incident_id']}/explanation", primary["headers"], query_counter),
    }
    db = Session()
    tools = IncidentCopilotTools()
    context_latencies = []
    context_queries = []
    context_sizes = []
    for _ in range(5):
        query_counter["count"] = 0
        started = time.perf_counter()
        context = tools.build_context(db, dataset["tenants"][0]["tenant_id"], primary["incident_id"])
        context_latencies.append((time.perf_counter() - started) * 1000)
        context_queries.append(query_counter["count"])
        context_sizes.append(len(json.dumps(context, default=str).encode("utf-8")))
    db.close()
    results["copilot_context"] = {
        "median_ms": round(statistics.median(context_latencies), 2),
        "p95_ms": round(percentile(context_latencies, 0.95), 2),
        "queries": statistics.median(context_queries),
        "bytes": int(statistics.median(context_sizes)),
        "stats": context.get("context_stats", {}),
    }

    tracemalloc.start()
    initial = tracemalloc.take_snapshot()
    for _ in range(20):
        client.get(f"/api/v1/incidents/{primary['incident_id']}/explanation", headers=primary["headers"])
    final = tracemalloc.take_snapshot()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    results["repeated_memory"] = {
        "requests": 20,
        "net_kib": round(sum(item.size_diff for item in final.compare_to(initial, "lineno")) / 1024, 2),
        "peak_kib": round(peak / 1024, 2),
    }

    del app.dependency_overrides[get_current_user]

    original_provider = ai_module.llm_provider.generate_text
    load_provider_attempts = 0
    load_provider_guard = threading.Lock()

    def deterministic_provider(*_args, **_kwargs):
        nonlocal load_provider_attempts
        with load_provider_guard:
            load_provider_attempts += 1
        return None

    ai_module.llm_provider.generate_text = deterministic_provider
    operations = ("list", "detail", "explanation", "conversations", "chat")

    request_records: list[dict[str, Any]] = []
    http_request_guard = threading.Lock()

    def counted_request(method: str, path: str, operation: str, **kwargs):
        request_started = time.perf_counter()
        response = getattr(client, method)(path, **kwargs)
        elapsed_ms = (time.perf_counter() - request_started) * 1000
        with http_request_guard:
            request_records.append({
                "status": response.status_code,
                "latency_ms": elapsed_ms,
                "bytes": len(response.content),
                "operation": operation,
                "response": response.text[:500] if response.status_code >= 400 else "",
            })
        return response

    def execute(number: int) -> tuple[int, float, int, str, str]:
        context = tenant_contexts[number % len(tenant_contexts)]
        operation = operations[number % len(operations)]
        incident_id = context["incident_id"]
        started = time.perf_counter()
        if operation == "list":
            response = counted_request("get", "/api/v1/incidents?page=1&page_size=20", operation, headers=context["headers"])
        elif operation == "detail":
            response = counted_request("get", f"/api/v1/incidents/{incident_id}", operation, headers=context["headers"])
        elif operation == "explanation":
            response = counted_request("get", f"/api/v1/incidents/{incident_id}/explanation", operation, headers=context["headers"])
        elif operation == "conversations":
            response = counted_request("get", f"/api/v1/ai/incident/{incident_id}/conversations?limit=20&offset=0", operation, headers=context["headers"])
        else:
            request_headers = {**context["headers"], "X-Request-ID": f"batch63-{concurrency}-{number}"}
            response = counted_request(
                "post",
                f"/api/v1/ai/incident/{incident_id}/chat",
                operation,
                headers=request_headers,
                json={"message": "What evidence supports this incident?"},
            )
            if response.status_code == 200:
                retry = counted_request(
                    "post",
                    f"/api/v1/ai/incident/{incident_id}/chat",
                    "chat_replay",
                    headers=request_headers,
                    json={"message": "What evidence supports this incident?"},
                )
                if retry.status_code != 200 or retry.json()["conversation_id"] != response.json()["conversation_id"]:
                    response = retry
        return response.status_code, (time.perf_counter() - started) * 1000, len(response.content), operation, response.text[:500]

    process = psutil.Process(os.getpid()) if psutil else None
    memory_samples: list[int] = []
    memory_stop = threading.Event()

    def sample_memory():
        while not memory_stop.wait(0.05):
            if process:
                memory_samples.append(process.memory_info().rss)

    memory_thread = threading.Thread(target=sample_memory, daemon=True)
    if process:
        memory_samples.append(process.memory_info().rss)
        memory_thread.start()
    started = time.perf_counter()
    samples = []
    worker_exceptions: list[dict[str, str]] = []
    try:
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [executor.submit(execute, number) for number in range(requests_count)]
            for future in as_completed(futures):
                try:
                    samples.append(future.result())
                except Exception as exc:
                    worker_exceptions.append({"type": type(exc).__name__, "message": str(exc)})
    finally:
        ai_module.llm_provider.generate_text = original_provider
        memory_stop.set()
        if process:
            memory_thread.join(timeout=1)
            memory_samples.append(process.memory_info().rss)
    duration = time.perf_counter() - started
    latencies = [record["latency_ms"] for record in request_records]
    errors = [record for record in request_records if record["status"] >= 400]
    validation_db = Session()
    try:
        tenant_leak_status = client.get(
            f"/api/v1/incidents/{dataset['tenants'][1]['incident_id']}",
            headers=tenant_contexts[0]["headers"],
        ).status_code
        messages = validation_db.query(AIInvestigationMessage).filter(
            AIInvestigationMessage.created_at >= datetime.now(timezone.utc) - timedelta(hours=1)
        ).all()
        request_roles: dict[str, list[str]] = {}
        for message in messages:
            request_id = (message.message_metadata or {}).get("request_id")
            if request_id and str(request_id).startswith(f"batch63-{concurrency}-"):
                request_roles.setdefault(str(request_id), []).append(message.role)
        duplicate_request_records = {
            request_id: roles
            for request_id, roles in request_roles.items()
            if sorted(roles) != ["assistant", "user"]
        }
        final_risk_scores = {
            item.id: float(item.risk_score or 0)
            for item in validation_db.query(Incident).filter(
                Incident.id.in_([tenant["incident_id"] for tenant in dataset["tenants"]])
            ).all()
        }
        relationship_counts = {
            "incident_alerts": validation_db.query(IncidentAlert).count(),
            "entities": validation_db.query(IncidentEntity).count(),
            "evidence": validation_db.query(IncidentEvidence).count(),
            "conversations": validation_db.query(AIInvestigationConversation).count(),
            "messages": validation_db.query(AIInvestigationMessage).count(),
            "memberships": validation_db.query(OrganizationMembership).count(),
        }
    finally:
        validation_db.close()

    results["concurrent_load"] = {
        "concurrency": concurrency,
        "operations": requests_count,
        "total_requests": len(request_records),
        "successful_requests": len(request_records) - len(errors),
        "failed_requests": len(errors) + len(worker_exceptions),
        "duration_seconds": round(duration, 2),
        "requests_per_second": round(len(request_records) / duration, 2),
        "success_rate_percent": round((len(request_records) - len(errors)) * 100 / len(request_records), 2),
        "median_ms": round(statistics.median(latencies), 2),
        "p95_ms": round(percentile(latencies, 0.95), 2),
        "p99_ms": round(percentile(latencies, 0.99), 2),
        "maximum_ms": round(max(latencies), 2),
        "error_rate_percent": round((len(errors) + len(worker_exceptions)) * 100 / max(1, len(request_records) + len(worker_exceptions)), 2),
        "status_codes": {
            str(code): sum(1 for record in request_records if record["status"] == code)
            for code in sorted({record["status"] for record in request_records})
        },
        "median_response_bytes": int(statistics.median(record["bytes"] for record in request_records)),
        "errors": errors,
        "worker_exceptions": worker_exceptions,
        "database_errors": [item for item in errors + worker_exceptions if "database" in json.dumps(item).lower()],
        "deadlocks": [item for item in errors + worker_exceptions if "deadlock" in json.dumps(item).lower()],
        "transaction_failures": [item for item in errors + worker_exceptions if "transaction" in json.dumps(item).lower()],
        "memory_rss_start_mib": round(memory_samples[0] / 1024 / 1024, 2) if memory_samples else None,
        "memory_rss_peak_mib": round(max(memory_samples) / 1024 / 1024, 2) if memory_samples else None,
        "tenant_leak_status": tenant_leak_status,
        "duplicate_request_records": duplicate_request_records,
        "provider_attempts": load_provider_attempts,
        "risk_scores_after_load": final_risk_scores,
        "relationship_counts_after_load": relationship_counts,
        "pool": dict(pool_stats),
    }
    results["copilot_idempotency"] = {
        "redis_available": verify_copilot_idempotency(
            client, Session, dataset, tenant_contexts, concurrency, redis_available=True
        ),
        "redis_unavailable": verify_copilot_idempotency(
            client, Session, dataset, tenant_contexts, concurrency, redis_available=False
        ),
    }
    app.dependency_overrides.clear()
    time.sleep(0.1)
    results["concurrent_load"]["pool"]["active_after_cleanup"] = pool_stats["active"]
    results["concurrent_load"]["pool"]["status_after_cleanup"] = engine.pool.status()
    client.close()
    return results


def run(concurrency: int, requests_count: int, database_url: str | None = None) -> dict[str, Any]:
    with validation_database(database_url) as (engine, target):
        try:
            return _run_with_engine(concurrency, requests_count, engine, target)
        finally:
            app.dependency_overrides.clear()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run isolated incident performance and concurrency validation.")
    parser.add_argument("--concurrency", type=int, default=8, choices=range(1, 33))
    parser.add_argument("--requests", type=int, default=100)
    parser.add_argument("--database-url", default=None, help="Optional isolated PostgreSQL validation database URL")
    parser.add_argument("--output", default=None, help="Write the JSON result to this file")
    args = parser.parse_args()
    result = run(args.concurrency, args.requests, args.database_url)
    payload = json.dumps(result, indent=2, default=str)
    if args.output:
        Path(args.output).write_text(payload + "\n", encoding="utf-8")
        print(f"Validation result written to {args.output}", file=sys.stderr)
    else:
        print(payload)
    load = result["concurrent_load"]
    idempotency_failures = [
        mode for mode, check in result["copilot_idempotency"].items()
        if check["provider_attempts_for_duplicate_scope"] != 1
        or not check["replays_match"]
        or check["request_message_roles"] != ["assistant", "user"]
        or check["different_question_status"] != 400
        or check["other_user_read_status"] != 404
        or check["cross_tenant_read_status"] != 404
        or check["other_incident_read_status"] != 404
        or check["retry_after_interruption_status"] != 200
        or check["interrupted_request_roles_after_retry"] != ["assistant", "user"]
        or check["local_locks_remaining"] != 0
    ]
    if (
        load["failed_requests"]
        or load["tenant_leak_status"] != 404
        or load["duplicate_request_records"]
        or load["pool"]["active_after_cleanup"] != 0
        or any(score != 78.0 for score in load["risk_scores_after_load"].values())
        or idempotency_failures
    ):
        raise SystemExit(1)
