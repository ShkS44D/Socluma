from types import SimpleNamespace

import pytest

from src.models.sqlalchemy import IndicatorType
from src.services.ioc_intelligence_service import (
    IOCValidationError,
    calculate_risk,
    ioc_intelligence_service,
    normalize_ioc,
)
from src.services.ioc_exchange_service import parse_stix_bundle, validate_sync_url


@pytest.mark.parametrize(
    ("kind", "submitted", "expected_type", "expected"),
    [
        ("ip", " 192.0.2.1 ", "ipv4", "192.0.2.1"),
        ("ipv6", "2001:0db8::1", "ipv6", "2001:db8::1"),
        ("cidr", "192.0.2.9/24", "cidr", "192.0.2.0/24"),
        ("domain", "Example[.]COM", "domain", "example.com"),
        ("domain", "täst.example", "domain", "xn--tst-qla.example"),
        ("url", "hxxps[:]//Example[.]COM/a", "url", "https://example.com/a"),
        ("email", "User@Example[.]COM", "email", "User@example.com"),
        ("hash", "D41D8CD98F00B204E9800998ECF8427E", "md5", "d41d8cd98f00b204e9800998ecf8427e"),
        ("sha256", "A" * 64, "sha256", "a" * 64),
        ("file_path", r"C:/Temp/Evil.exe", "file_path", r"C:\Temp\Evil.exe"),
    ],
)
def test_deterministic_normalization(kind, submitted, expected_type, expected):
    result = normalize_ioc(kind, submitted)
    assert result.type == expected_type
    assert result.canonical == expected
    assert result == normalize_ioc(kind, submitted)


@pytest.mark.parametrize("kind,value", [
    ("ipv4", "999.1.1.1"), ("domain", "invalid"), ("url", "file:///etc/passwd"),
    ("sha256", "abc"), ("email", "not-an-email"), ("unknown", "value"),
])
def test_invalid_values_are_rejected(kind, value):
    with pytest.raises(IOCValidationError):
        normalize_ioc(kind, value)


def test_lifecycle_requires_reason_and_blocks_invalid_transition():
    ioc = SimpleNamespace(
        lifecycle_status="active", is_active=True, false_positive=False, allowlisted=False,
        expired_at=None, revoked_at=None,
    )
    with pytest.raises(IOCValidationError):
        ioc_intelligence_service.transition(ioc, "allowlisted")
    ioc_intelligence_service.transition(ioc, "allowlisted", "Approved corporate infrastructure")
    assert ioc.lifecycle_status == "allowlisted"
    assert ioc.allowlisted is True
    assert ioc.is_active is False


def test_explainable_risk_separates_confidence_reliability_and_sightings():
    ioc = SimpleNamespace(
        confidence_score=80, source_reliability=70, internal_sighting_count=3,
        last_internal_sighting=None, allowlisted=False, false_positive=False,
        lifecycle_status="active",
    )
    score, reasons = calculate_risk(ioc, [{"verdict": "malicious"}, {"verdict": "clean"}])
    assert 0 < score <= 100
    factors = {item["factor"] for item in reasons}
    assert {"confidence", "source_reliability", "provider_consensus", "provider_conflict", "internal_sightings"} <= factors


def test_stix_supported_and_unsupported_patterns_are_reported():
    result = parse_stix_bundle({
        "type": "bundle", "id": "bundle--00000000-0000-4000-8000-000000000001",
        "objects": [
            {
                "type": "indicator", "spec_version": "2.1",
                "id": "indicator--00000000-0000-4000-8000-000000000002",
                "pattern": "[domain-name:value = 'evil[.]example']",
            },
            {
                "type": "indicator", "spec_version": "2.1",
                "id": "indicator--00000000-0000-4000-8000-000000000003",
                "pattern": "[process:name = 'unsupported.exe']",
            },
        ],
    })
    assert result["indicators"][0]["normalized_value"] == "evil.example"
    assert result["unsupported"][0]["reason"] == "STIX_PATTERN_UNSUPPORTED"


@pytest.mark.parametrize("url", [
    "http://example.com/taxii", "file:///tmp/feed", "https://127.0.0.1/feed",
    "https://169.254.169.254/latest/meta-data", "https://user:pass@example.com/feed",
])
def test_sync_url_ssrf_guards(url):
    with pytest.raises(IOCValidationError):
        validate_sync_url(url)
