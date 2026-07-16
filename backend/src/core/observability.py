from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Iterator

from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST


API_REQUEST_LATENCY = Histogram(
    "triageops_api_request_duration_seconds",
    "HTTP API request latency.",
    ["method", "endpoint", "status_code"],
)
API_REQUESTS = Counter(
    "triageops_api_requests_total",
    "HTTP API requests.",
    ["method", "endpoint", "status_code"],
)
AUTH_ATTEMPTS = Counter(
    "triageops_auth_attempts_total",
    "Authentication attempts.",
    ["outcome"],
)
COLLECTOR_HEARTBEATS = Counter(
    "triageops_collector_heartbeats_total",
    "Collector heartbeat submissions.",
    ["status"],
)
COLLECTOR_EVENTS = Counter(
    "triageops_collector_events_total",
    "Collector event ingestion submissions.",
    ["source"],
)
DETECTION_EXECUTIONS = Counter(
    "triageops_detection_executions_total",
    "Detection engine executions.",
    ["outcome"],
)
DETECTION_LATENCY = Histogram(
    "triageops_detection_duration_seconds",
    "Detection engine execution time.",
)
ALERTS_CREATED = Counter(
    "triageops_alerts_created_total",
    "Alerts created.",
    ["source"],
)
INCIDENTS_CREATED = Counter(
    "triageops_incidents_created_total",
    "Incidents created.",
    ["source"],
)
WEBSOCKET_CONNECTIONS = Gauge(
    "triageops_websocket_connections",
    "Active WebSocket connections.",
)
WEBSOCKET_EVENTS = Counter(
    "triageops_websocket_events_total",
    "WebSocket connection lifecycle and broadcast events.",
    ["event"],
)
REDIS_STATUS = Gauge(
    "triageops_redis_up",
    "Redis health status, 1 for up and 0 for down.",
)
DATABASE_STATUS = Gauge(
    "triageops_database_up",
    "Database health status, 1 for up and 0 for down.",
)
DATABASE_LATENCY = Histogram(
    "triageops_database_latency_seconds",
    "Database health probe latency.",
    ["operation"],
)
QUEUE_LATENCY = Histogram(
    "triageops_queue_latency_seconds",
    "Background queue health probe latency.",
    ["operation"],
)
WORKER_EXECUTION_TIME = Histogram(
    "triageops_worker_execution_duration_seconds",
    "Background worker task execution time.",
    ["task", "outcome"],
)
CONNECTOR_EXECUTIONS = Counter(
    "triageops_connector_executions_total",
    "SOAR connector executions.",
    ["connector_type", "status"],
)
CONNECTOR_FAILURES = Counter(
    "triageops_connector_failures_total",
    "SOAR connector failures.",
    ["connector_type", "reason"],
)
CONNECTOR_RETRIES = Counter(
    "triageops_connector_retries_total",
    "SOAR connector retries.",
    ["connector_type"],
)
CONNECTOR_TIMEOUTS = Counter(
    "triageops_connector_timeouts_total",
    "SOAR connector timeouts.",
    ["connector_type"],
)
CONNECTOR_EXECUTION_DURATION = Histogram(
    "triageops_connector_execution_duration_seconds",
    "SOAR connector execution duration.",
    ["connector_type", "status"],
)
CONNECTOR_APPROVAL_LATENCY = Histogram(
    "triageops_connector_approval_latency_seconds",
    "SOAR action approval latency.",
    ["status"],
)
INCIDENT_EXPLANATIONS = Counter(
    "triageops_incident_explanations_total",
    "Deterministic incident explanations generated.",
    ["outcome"],
)
COPILOT_REQUESTS = Counter(
    "triageops_copilot_requests_total",
    "Incident Copilot requests.",
    ["provider", "outcome"],
)
COPILOT_RESPONSE_LATENCY = Histogram(
    "triageops_copilot_response_duration_seconds",
    "Incident Copilot response latency.",
    ["provider", "fallback_used"],
)
COPILOT_PROVIDER_FAILURES = Counter(
    "triageops_copilot_provider_failures_total",
    "External Copilot provider failures.",
    ["provider"],
)
COPILOT_FALLBACK_USAGE = Counter(
    "triageops_copilot_fallback_total",
    "Deterministic Copilot fallback usage.",
    ["reason"],
)
COPILOT_EVIDENCE_REFERENCES = Histogram(
    "triageops_copilot_evidence_references",
    "Evidence references returned per Copilot response.",
)
COPILOT_TOKENS = Counter(
    "triageops_copilot_tokens_total",
    "OpenAI Copilot tokens by normalized usage category.",
    ["provider", "type"],
)
COPILOT_CONVERSATIONS = Counter(
    "triageops_copilot_conversations_total",
    "Incident Copilot conversations created.",
)
INCIDENT_CORRELATION_CONFIDENCE = Histogram(
    "triageops_incident_correlation_confidence",
    "Stored incident correlation confidence score.",
)
INCIDENT_SOURCE_ALERTS = Histogram(
    "triageops_incident_source_alerts",
    "Source alerts represented in an incident explanation.",
)
INCIDENT_SOURCE_EVENTS = Histogram(
    "triageops_incident_source_events",
    "Source events represented in an incident explanation.",
)


@contextmanager
def timed_histogram(histogram: Histogram, *labels: str) -> Iterator[None]:
    start = time.perf_counter()
    try:
        yield
    finally:
        histogram.labels(*labels).observe(time.perf_counter() - start)


@contextmanager
def timed_detection() -> Iterator[None]:
    start = time.perf_counter()
    try:
        yield
        DETECTION_EXECUTIONS.labels("success").inc()
    except Exception:
        DETECTION_EXECUTIONS.labels("error").inc()
        raise
    finally:
        DETECTION_LATENCY.observe(time.perf_counter() - start)


def metrics_response() -> tuple[bytes, str]:
    return generate_latest(), CONTENT_TYPE_LATEST
