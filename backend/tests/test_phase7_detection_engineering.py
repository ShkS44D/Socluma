from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from src.services.detection_lifecycle_service import detection_lifecycle_service


def event(identity: str, seconds: int, **normalized):
    return SimpleNamespace(
        id=identity,
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds),
        source="phase7-test",
        severity="medium",
        normalized_event=normalized,
        raw_event={},
    )


def condition(field="user.name", operator="eq", value="alice"):
    return {"field": field, "operator": operator, "value": value}


def test_validation_is_deterministic_and_hash_bound():
    definition = {"kind": "event_match", "conditions": [condition()]}
    first = detection_lifecycle_service.validate(definition)
    second = detection_lifecycle_service.validate(definition)
    assert first == second
    assert first["valid"] is True
    assert len(first["content_hash"]) == 64


def test_validation_rejects_unknown_field_and_unsafe_regex():
    report = detection_lifecycle_service.validate({
        "kind": "event_match",
        "conditions": [
            condition("does.not.exist"),
            condition("message", "regex", "(a+)+$"),
        ],
    })
    assert report["valid"] is False
    assert {item["code"] for item in report["errors"]} == {
        "DETECTION_FIELD_UNSUPPORTED",
        "DETECTION_REGEX_UNSAFE",
    }


def test_event_threshold_frequency_and_aggregation():
    rows = [
        event("1", 0, actor={"user": "alice"}, network={"dst_ip": "10.0.0.1"}),
        event("2", 1, actor={"user": "alice"}, network={"dst_ip": "10.0.0.2"}),
        event("3", 2, actor={"user": "bob"}, network={"dst_ip": "10.0.0.2"}),
    ]
    event_result = detection_lifecycle_service.evaluate_events({
        "kind": "event_match", "conditions": [condition()],
    }, rows)
    assert event_result["matches"] == 2
    for kind in ("threshold", "frequency"):
        result = detection_lifecycle_service.evaluate_events({
            "kind": kind, "conditions": [condition()], "threshold": 2,
            "window_seconds": 60, "group_by": ["user.name"],
        }, rows)
        assert result["estimated_alert_count"] == 1
    aggregate = detection_lifecycle_service.evaluate_events({
        "kind": "aggregation", "conditions": [condition()],
        "aggregation": {"function": "distinct_count", "field": "destination.ip"},
        "threshold": 2, "window_seconds": 60, "group_by": ["user.name"],
    }, rows)
    assert aggregate["aggregate_values"]["alice"] == 2
    assert aggregate["estimated_alert_count"] == 1


def test_sequence_requires_order_and_group_isolation():
    definition = {
        "kind": "sequence", "window_seconds": 60, "group_by": ["user.name"],
        "steps": [
            {"conditions": [condition("event.outcome", "eq", "failure")]},
            {"conditions": [condition("event.outcome", "eq", "success")]},
        ],
    }
    matching = [
        event("1", 0, actor={"user": "alice"}, event={"outcome": "failure"}),
        event("2", 1, actor={"user": "bob"}, event={"outcome": "success"}),
        event("3", 2, actor={"user": "alice"}, event={"outcome": "success"}),
    ]
    result = detection_lifecycle_service.evaluate_events(definition, matching)
    assert result["estimated_alert_count"] == 1
    assert result["groups"] == {"alice": 2}
    reversed_rows = list(reversed(matching[:1] + matching[2:]))
    result = detection_lifecycle_service.evaluate_events(definition, reversed_rows)
    # The evaluator sorts by event timestamp, so input order cannot change the result.
    assert result["estimated_alert_count"] == 1


def test_correlation_requires_every_rule():
    rows = [
        {"id": "m1", "rule_id": "rule-a", "timestamp": datetime.now(timezone.utc), "source": "match"},
        {"id": "m2", "rule_id": "rule-b", "timestamp": datetime.now(timezone.utc), "source": "match"},
    ]
    result = detection_lifecycle_service.evaluate_events({
        "kind": "correlation", "rule_ids": ["rule-a", "rule-b"], "window_seconds": 60,
    }, rows)
    assert result["estimated_alert_count"] == 1
    assert result["matches"] == 2


def test_safe_regex_runtime_is_bounded():
    assert detection_lifecycle_service.safe_regex(r"powershell(\.exe)?") is True
    assert detection_lifecycle_service.safe_regex(r"(a+)+$") is False
    candidate = event("1", 0, message="a" * 100_000 + "!")
    assert detection_lifecycle_service._event_matches(
        [condition("message", "regex", r"(a+)+$")], candidate
    ) is False
