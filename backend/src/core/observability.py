from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Iterator

from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST


API_REQUEST_LATENCY = Histogram(
    "socluma_api_request_duration_seconds",
    "HTTP API request latency.",
    ["method", "endpoint", "status_code"],
)
API_REQUESTS = Counter(
    "socluma_api_requests_total",
    "HTTP API requests.",
    ["method", "endpoint", "status_code"],
)
AUTH_ATTEMPTS = Counter(
    "socluma_auth_attempts_total",
    "Authentication attempts.",
    ["outcome"],
)
COLLECTOR_HEARTBEATS = Counter(
    "socluma_collector_heartbeats_total",
    "Collector heartbeat submissions.",
    ["status"],
)
COLLECTOR_EVENTS = Counter(
    "socluma_collector_events_total",
    "Collector event ingestion submissions.",
    ["source"],
)
INGESTION_BATCHES = Counter(
    "socluma_ingestion_batches_total",
    "Telemetry batch outcomes.",
    ["outcome"],
)
INGESTION_EVENT_OUTCOMES = Counter(
    "socluma_ingestion_event_outcomes_total",
    "Per-event telemetry ingestion outcomes.",
    ["outcome"],
)
INGESTION_BATCH_SIZE = Histogram(
    "socluma_ingestion_batch_size",
    "Events submitted per telemetry batch.",
)
INGESTION_QUALITY = Histogram(
    "socluma_ingestion_quality_score",
    "Normalized telemetry data quality score.",
    buckets=(0, 25, 50, 75, 90, 100),
)
INGESTION_LAG = Histogram(
    "socluma_ingestion_lag_seconds",
    "Telemetry event-time to receive-time lag.",
)
INGESTION_DEAD_LETTER = Counter(
    "socluma_ingestion_dead_letter_total",
    "Telemetry records moved to dead-letter state.",
    ["stage", "error_code"],
)
DETECTION_EXECUTIONS = Counter(
    "socluma_detection_executions_total",
    "Detection engine executions.",
    ["outcome"],
)
DETECTION_LATENCY = Histogram(
    "socluma_detection_duration_seconds",
    "Detection engine execution time.",
)
ALERTS_CREATED = Counter(
    "socluma_alerts_created_total",
    "Alerts created.",
    ["source"],
)
INCIDENTS_CREATED = Counter(
    "socluma_incidents_created_total",
    "Incidents created.",
    ["source"],
)
WEBSOCKET_CONNECTIONS = Gauge(
    "socluma_websocket_connections",
    "Active WebSocket connections.",
)
WEBSOCKET_EVENTS = Counter(
    "socluma_websocket_events_total",
    "WebSocket connection lifecycle and broadcast events.",
    ["event"],
)
REDIS_STATUS = Gauge(
    "socluma_redis_up",
    "Redis health status, 1 for up and 0 for down.",
)
DATABASE_STATUS = Gauge(
    "socluma_database_up",
    "Database health status, 1 for up and 0 for down.",
)
DATABASE_LATENCY = Histogram(
    "socluma_database_latency_seconds",
    "Database health probe latency.",
    ["operation"],
)
QUEUE_LATENCY = Histogram(
    "socluma_queue_latency_seconds",
    "Background queue health probe latency.",
    ["operation"],
)
WORKER_EXECUTION_TIME = Histogram(
    "socluma_worker_execution_duration_seconds",
    "Background worker task execution time.",
    ["task", "outcome"],
)
CONNECTOR_EXECUTIONS = Counter(
    "socluma_connector_executions_total",
    "SOAR connector executions.",
    ["connector_type", "status"],
)
CONNECTOR_FAILURES = Counter(
    "socluma_connector_failures_total",
    "SOAR connector failures.",
    ["connector_type", "reason"],
)
CONNECTOR_RETRIES = Counter(
    "socluma_connector_retries_total",
    "SOAR connector retries.",
    ["connector_type"],
)
CONNECTOR_TIMEOUTS = Counter(
    "socluma_connector_timeouts_total",
    "SOAR connector timeouts.",
    ["connector_type"],
)
CONNECTOR_EXECUTION_DURATION = Histogram(
    "socluma_connector_execution_duration_seconds",
    "SOAR connector execution duration.",
    ["connector_type", "status"],
)
CONNECTOR_APPROVAL_LATENCY = Histogram(
    "socluma_connector_approval_latency_seconds",
    "SOAR action approval latency.",
    ["status"],
)
INCIDENT_EXPLANATIONS = Counter(
    "socluma_incident_explanations_total",
    "Deterministic incident explanations generated.",
    ["outcome"],
)
COPILOT_REQUESTS = Counter(
    "socluma_copilot_requests_total",
    "Socluma Copilot incident requests.",
    ["provider", "outcome"],
)
COPILOT_RESPONSE_LATENCY = Histogram(
    "socluma_copilot_response_duration_seconds",
    "Socluma Copilot incident response latency.",
    ["provider", "fallback_used"],
)
COPILOT_PROVIDER_FAILURES = Counter(
    "socluma_copilot_provider_failures_total",
    "External Socluma Copilot provider failures.",
    ["provider"],
)
COPILOT_FALLBACK_USAGE = Counter(
    "socluma_copilot_fallback_total",
    "Deterministic Socluma Copilot fallback usage.",
    ["reason"],
)
COPILOT_EVIDENCE_REFERENCES = Histogram(
    "socluma_copilot_evidence_references",
    "Evidence references returned per Socluma Copilot response.",
)
COPILOT_TOKENS = Counter(
    "socluma_copilot_tokens_total",
    "OpenAI token usage for Socluma Copilot by normalized category.",
    ["provider", "type"],
)
COPILOT_CONVERSATIONS = Counter(
    "socluma_copilot_conversations_total",
    "Socluma Copilot incident conversations created.",
)
INCIDENT_CORRELATION_CONFIDENCE = Histogram(
    "socluma_incident_correlation_confidence",
    "Stored incident correlation confidence score.",
)
INCIDENT_SOURCE_ALERTS = Histogram(
    "socluma_incident_source_alerts",
    "Source alerts represented in an incident explanation.",
)
INCIDENT_SOURCE_EVENTS = Histogram(
    "socluma_incident_source_events",
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
