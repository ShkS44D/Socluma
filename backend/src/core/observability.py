from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Iterator

from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST


API_REQUEST_LATENCY = Histogram(
    "vigilantai_api_request_duration_seconds",
    "HTTP API request latency.",
    ["method", "endpoint", "status_code"],
)
API_REQUESTS = Counter(
    "vigilantai_api_requests_total",
    "HTTP API requests.",
    ["method", "endpoint", "status_code"],
)
AUTH_ATTEMPTS = Counter(
    "vigilantai_auth_attempts_total",
    "Authentication attempts.",
    ["outcome"],
)
COLLECTOR_HEARTBEATS = Counter(
    "vigilantai_collector_heartbeats_total",
    "Collector heartbeat submissions.",
    ["status"],
)
COLLECTOR_EVENTS = Counter(
    "vigilantai_collector_events_total",
    "Collector event ingestion submissions.",
    ["source"],
)
INGESTION_BATCHES = Counter(
    "vigilantai_ingestion_batches_total",
    "Telemetry batch outcomes.",
    ["outcome"],
)
INGESTION_EVENT_OUTCOMES = Counter(
    "vigilantai_ingestion_event_outcomes_total",
    "Per-event telemetry ingestion outcomes.",
    ["outcome"],
)
INGESTION_BATCH_SIZE = Histogram(
    "vigilantai_ingestion_batch_size",
    "Events submitted per telemetry batch.",
)
INGESTION_QUALITY = Histogram(
    "vigilantai_ingestion_quality_score",
    "Normalized telemetry data quality score.",
    buckets=(0, 25, 50, 75, 90, 100),
)
INGESTION_LAG = Histogram(
    "vigilantai_ingestion_lag_seconds",
    "Telemetry event-time to receive-time lag.",
)
INGESTION_DEAD_LETTER = Counter(
    "vigilantai_ingestion_dead_letter_total",
    "Telemetry records moved to dead-letter state.",
    ["stage", "error_code"],
)
DETECTION_EXECUTIONS = Counter(
    "vigilantai_detection_executions_total",
    "Detection engine executions.",
    ["outcome"],
)
DETECTION_LATENCY = Histogram(
    "vigilantai_detection_duration_seconds",
    "Detection engine execution time.",
)
ALERTS_CREATED = Counter(
    "vigilantai_alerts_created_total",
    "Alerts created.",
    ["source"],
)
INCIDENTS_CREATED = Counter(
    "vigilantai_incidents_created_total",
    "Incidents created.",
    ["source"],
)
WEBSOCKET_CONNECTIONS = Gauge(
    "vigilantai_websocket_connections",
    "Active WebSocket connections.",
)
WEBSOCKET_EVENTS = Counter(
    "vigilantai_websocket_events_total",
    "WebSocket connection lifecycle and broadcast events.",
    ["event"],
)
REDIS_STATUS = Gauge(
    "vigilantai_redis_up",
    "Redis health status, 1 for up and 0 for down.",
)
DATABASE_STATUS = Gauge(
    "vigilantai_database_up",
    "Database health status, 1 for up and 0 for down.",
)
DATABASE_LATENCY = Histogram(
    "vigilantai_database_latency_seconds",
    "Database health probe latency.",
    ["operation"],
)
QUEUE_LATENCY = Histogram(
    "vigilantai_queue_latency_seconds",
    "Background queue health probe latency.",
    ["operation"],
)
WORKER_EXECUTION_TIME = Histogram(
    "vigilantai_worker_execution_duration_seconds",
    "Background worker task execution time.",
    ["task", "outcome"],
)
CONNECTOR_EXECUTIONS = Counter(
    "vigilantai_connector_executions_total",
    "SOAR connector executions.",
    ["connector_type", "status"],
)
CONNECTOR_FAILURES = Counter(
    "vigilantai_connector_failures_total",
    "SOAR connector failures.",
    ["connector_type", "reason"],
)
CONNECTOR_RETRIES = Counter(
    "vigilantai_connector_retries_total",
    "SOAR connector retries.",
    ["connector_type"],
)
CONNECTOR_TIMEOUTS = Counter(
    "vigilantai_connector_timeouts_total",
    "SOAR connector timeouts.",
    ["connector_type"],
)
CONNECTOR_EXECUTION_DURATION = Histogram(
    "vigilantai_connector_execution_duration_seconds",
    "SOAR connector execution duration.",
    ["connector_type", "status"],
)
CONNECTOR_APPROVAL_LATENCY = Histogram(
    "vigilantai_connector_approval_latency_seconds",
    "SOAR action approval latency.",
    ["status"],
)
INCIDENT_EXPLANATIONS = Counter(
    "vigilantai_incident_explanations_total",
    "Deterministic incident explanations generated.",
    ["outcome"],
)
COPILOT_REQUESTS = Counter(
    "vigilantai_copilot_requests_total",
    "VigilantAI Copilot incident requests.",
    ["provider", "outcome"],
)
COPILOT_RESPONSE_LATENCY = Histogram(
    "vigilantai_copilot_response_duration_seconds",
    "VigilantAI Copilot incident response latency.",
    ["provider", "fallback_used"],
)
COPILOT_PROVIDER_FAILURES = Counter(
    "vigilantai_copilot_provider_failures_total",
    "External VigilantAI Copilot provider failures.",
    ["provider"],
)
COPILOT_FALLBACK_USAGE = Counter(
    "vigilantai_copilot_fallback_total",
    "Deterministic VigilantAI Copilot fallback usage.",
    ["reason"],
)
COPILOT_EVIDENCE_REFERENCES = Histogram(
    "vigilantai_copilot_evidence_references",
    "Evidence references returned per VigilantAI Copilot response.",
)
COPILOT_TOKENS = Counter(
    "vigilantai_copilot_tokens_total",
    "OpenAI token usage for VigilantAI Copilot by normalized category.",
    ["provider", "type"],
)
COPILOT_CONVERSATIONS = Counter(
    "vigilantai_copilot_conversations_total",
    "VigilantAI Copilot incident conversations created.",
)
INCIDENT_CORRELATION_CONFIDENCE = Histogram(
    "vigilantai_incident_correlation_confidence",
    "Stored incident correlation confidence score.",
)
INCIDENT_SOURCE_ALERTS = Histogram(
    "vigilantai_incident_source_alerts",
    "Source alerts represented in an incident explanation.",
)
INCIDENT_SOURCE_EVENTS = Histogram(
    "vigilantai_incident_source_events",
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
