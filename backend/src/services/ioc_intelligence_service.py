from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parseaddr
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.models.sqlalchemy import (
    IOC,
    IOCListEntry,
    IOCScoreHistory,
    IOCSighting,
    IndicatorType,
    SecurityEvent,
)
from src.utils.datetime_utils import ensure_utc, get_utc_now


class IOCValidationError(ValueError):
    error_code = "IOC_VALUE_INVALID"


class IOCDuplicateError(ValueError):
    error_code = "IOC_DUPLICATE"


LIFECYCLE_TRANSITIONS = {
    "new": {"under_review", "active", "archived"},
    "under_review": {"active", "monitoring", "false_positive", "allowlisted", "archived"},
    "active": {"monitoring", "false_positive", "allowlisted", "expired", "revoked", "archived"},
    "monitoring": {"active", "false_positive", "allowlisted", "expired", "revoked", "archived"},
    "false_positive": {"under_review", "archived"},
    "allowlisted": {"under_review", "archived"},
    "expired": {"under_review", "active", "archived"},
    "revoked": {"under_review", "archived"},
    "archived": {"under_review"},
}
MATCHABLE_STATES = {"active", "monitoring"}
REASON_REQUIRED_STATES = {"false_positive", "allowlisted", "revoked", "archived"}
TLP_VALUES = {"TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"}
HASH_LENGTH_TYPES = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


@dataclass(frozen=True)
class NormalizedIOC:
    type: str
    original: str
    canonical: str
    display: str
    content_hash: str
    warnings: tuple[str, ...] = ()


def _type_value(ioc_type: IndicatorType | str) -> str:
    return ioc_type.value if isinstance(ioc_type, IndicatorType) else str(ioc_type).lower()


def refang(value: str) -> str:
    value = value.strip()
    value = re.sub(r"(?i)^hxxps", "https", value)
    value = re.sub(r"(?i)^hxxp", "http", value)
    return value.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")


def _normalize_domain(value: str) -> tuple[str, list[str]]:
    candidate = value.rstrip(".").lower()
    warnings: list[str] = []
    try:
        ascii_domain = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise IOCValidationError("Domain contains invalid Unicode") from exc
    if ascii_domain != candidate:
        warnings.append("unicode_domain_converted_to_punycode")
    if len(ascii_domain) > 253 or "." not in ascii_domain:
        raise IOCValidationError("Domain must be a valid fully-qualified domain name")
    if any(not DOMAIN_LABEL_RE.fullmatch(label) for label in ascii_domain.split(".")):
        raise IOCValidationError("Domain contains an invalid label")
    return ascii_domain, warnings


def normalize_ioc(ioc_type: IndicatorType | str, value: str) -> NormalizedIOC:
    original = str(value)
    candidate = refang(original)
    kind = _type_value(ioc_type)
    warnings: list[str] = []

    if kind in {"ip", "ipv4", "ipv6"}:
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError as exc:
            raise IOCValidationError("Invalid IP address") from exc
        canonical = address.compressed.lower()
        kind = "ipv4" if address.version == 4 else "ipv6"
    elif kind == "cidr":
        try:
            canonical = str(ipaddress.ip_network(candidate, strict=False)).lower()
        except ValueError as exc:
            raise IOCValidationError("Invalid CIDR range") from exc
    elif kind == "domain":
        canonical, warnings = _normalize_domain(candidate)
    elif kind == "url":
        parsed = urlsplit(candidate)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise IOCValidationError("URL must use http or https and include a host")
        host, domain_warnings = _normalize_domain(parsed.hostname)
        warnings.extend(domain_warnings)
        port = parsed.port
        netloc = host
        if port and not ((parsed.scheme.lower() == "http" and port == 80) or (parsed.scheme.lower() == "https" and port == 443)):
            netloc = f"{host}:{port}"
        path = quote(unquote(parsed.path or "/"), safe="/:@-._~!$&'()*+,;=")
        canonical = urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))
    elif kind == "email":
        _, address = parseaddr(candidate)
        if address != candidate or address.count("@") != 1:
            raise IOCValidationError("Invalid email address")
        local, domain = address.rsplit("@", 1)
        normalized_domain, domain_warnings = _normalize_domain(domain)
        if not local or len(local) > 64:
            raise IOCValidationError("Invalid email local part")
        canonical = f"{local}@{normalized_domain}"
        warnings.extend(domain_warnings)
    elif kind in {"hash", "md5", "sha1", "sha256", "sha512", "certificate_fingerprint", "ja3", "ja4"}:
        compact = candidate.replace(":", "").lower()
        if not HEX_RE.fullmatch(compact):
            raise IOCValidationError("Hash or fingerprint must be hexadecimal")
        inferred = HASH_LENGTH_TYPES.get(len(compact))
        if kind == "hash":
            if not inferred:
                raise IOCValidationError("Hash must be MD5, SHA-1, SHA-256, or SHA-512")
            kind = inferred
        expected = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128, "ja3": 32}.get(kind)
        if expected and len(compact) != expected:
            raise IOCValidationError(f"{kind.upper()} value has an invalid length")
        if kind == "ja4" and not 16 <= len(compact) <= 128:
            raise IOCValidationError("JA4 fingerprint has an invalid length")
        canonical = compact
    elif kind in {"file_name", "file_path", "registry_key", "mutex", "user_agent", "cryptocurrency_address"}:
        canonical = candidate.strip()
        if not canonical or len(canonical) > 2048 or "\x00" in canonical:
            raise IOCValidationError("Indicator value is empty or exceeds the safe length")
        if kind in {"file_path", "registry_key"}:
            canonical = canonical.replace("/", "\\")
        if kind == "registry_key":
            canonical = canonical.upper()
    else:
        raise IOCValidationError(f"Unsupported IOC type: {kind}")

    digest = hashlib.sha256(f"{kind}\0{canonical}".encode("utf-8")).hexdigest()
    return NormalizedIOC(kind, original, canonical, canonical, digest, tuple(warnings))


def calculate_risk(ioc: IOC, provider_results: list[dict] | None = None) -> tuple[int, list[dict]]:
    providers = provider_results or []
    reasons: list[dict] = []
    score = 0

    def add(factor: str, contribution: int, explanation: str) -> None:
        nonlocal score
        score += contribution
        reasons.append({"factor": factor, "contribution": contribution, "explanation": explanation})

    add("confidence", round((ioc.confidence_score or 0) * 0.35), "IOC confidence contributes up to 35 points.")
    add("source_reliability", round((ioc.source_reliability or 0) * 0.2), "Source reliability contributes up to 20 points.")
    malicious = sum(1 for item in providers if item.get("verdict") in {"malicious", "suspicious"})
    clean = sum(1 for item in providers if item.get("verdict") in {"clean", "benign"})
    if malicious:
        add("provider_consensus", min(15, malicious * 5), f"{malicious} independent provider(s) reported risk.")
    if malicious and clean:
        add("provider_conflict", -5, "Providers disagree; analyst review is required.")
    if ioc.internal_sighting_count:
        add("internal_sightings", min(20, 5 + ioc.internal_sighting_count), f"Observed internally {ioc.internal_sighting_count} time(s).")
    if ioc.last_internal_sighting:
        age_hours = max(
            0,
            (get_utc_now() - ensure_utc(ioc.last_internal_sighting)).total_seconds()
            / 3600,
        )
        if age_hours <= 24:
            add("sighting_recency", 10, "IOC was observed internally within 24 hours.")
        elif age_hours <= 168:
            add("sighting_recency", 5, "IOC was observed internally within seven days.")
    if ioc.allowlisted:
        add("allowlist", -100, "Organization allowlist suppresses malicious operational risk.")
    if ioc.false_positive:
        add("false_positive", -100, "IOC is classified as a false positive.")
    if ioc.lifecycle_status in {"expired", "revoked", "archived"}:
        add("lifecycle", -50, f"IOC lifecycle is {ioc.lifecycle_status}.")
    return max(0, min(100, score)), reasons


class IOCIntelligenceService:
    def apply_normalization(self, ioc: IOC, submitted_type: IndicatorType | str, value: str) -> None:
        normalized = normalize_ioc(submitted_type, value)
        ioc.type = IndicatorType(normalized.type)
        ioc.value = normalized.canonical
        ioc.original_value = normalized.original
        ioc.normalized_value = normalized.canonical
        ioc.display_value = normalized.display
        ioc.content_hash = normalized.content_hash

    def transition(self, ioc: IOC, target: str, reason: str | None = None) -> None:
        current = ioc.lifecycle_status or ("active" if ioc.is_active else "new")
        if target not in LIFECYCLE_TRANSITIONS.get(current, set()):
            raise IOCValidationError(f"Transition from {current} to {target} is not allowed")
        if target in REASON_REQUIRED_STATES and not (reason or "").strip():
            raise IOCValidationError(f"A reason is required when moving an IOC to {target}")
        now = get_utc_now()
        ioc.lifecycle_status = target
        ioc.is_active = target in MATCHABLE_STATES
        ioc.false_positive = target == "false_positive"
        ioc.allowlisted = target == "allowlisted"
        if target == "expired":
            ioc.expired_at = now
        if target == "revoked":
            ioc.revoked_at = now

    def recalculate(self, db: Session, ioc: IOC, provider_results: list[dict] | None = None) -> IOC:
        score, reasons = calculate_risk(ioc, provider_results)
        ioc.risk_score = score
        ioc.risk_reasons = reasons
        ioc.risk_score_version = "1.0"
        db.add(IOCScoreHistory(
            tenant_id=ioc.tenant_id, ioc_id=ioc.id, score=score, version="1.0", reasons=reasons,
        ))
        return ioc

    def match_event(
        self,
        db: Session,
        event: SecurityEvent,
        *,
        ioc_id: str | None = None,
    ) -> list[IOCSighting]:
        values = self._flatten(event.normalized_event or {})
        if not values:
            return []
        now = get_utc_now()
        query = db.query(IOC).filter(
            IOC.tenant_id == event.tenant_id,
            IOC.lifecycle_status.in_(MATCHABLE_STATES),
            IOC.allowlisted.is_(False),
            IOC.false_positive.is_(False),
            or_(IOC.valid_until.is_(None), IOC.valid_until > now),
        )
        if ioc_id is not None:
            query = query.filter(IOC.id == ioc_id)
        iocs = query.all()
        sightings: list[IOCSighting] = []
        for ioc in iocs:
            for field, raw_value in values:
                try:
                    candidate = normalize_ioc(ioc.type, str(raw_value)).canonical
                except IOCValidationError:
                    continue
                if candidate != ioc.normalized_value:
                    continue
                existing = db.query(IOCSighting).filter(
                    IOCSighting.tenant_id == event.tenant_id,
                    IOCSighting.ioc_id == ioc.id,
                    IOCSighting.event_id == event.id,
                    IOCSighting.matched_field == field,
                ).first()
                if existing:
                    continue
                sighting = IOCSighting(
                    tenant_id=event.tenant_id, ioc_id=ioc.id, ioc_content_hash=ioc.content_hash,
                    event_id=event.id, collector_id=event.collector_id, data_source=event.source,
                    matched_field=field, matched_value=str(raw_value)[:2048],
                    first_observed=event.timestamp, last_observed=event.timestamp,
                )
                db.add(sighting)
                sightings.append(sighting)
                ioc.internal_sighting_count = (ioc.internal_sighting_count or 0) + 1
                ioc.first_internal_sighting = ioc.first_internal_sighting or event.timestamp
                ioc.last_internal_sighting = max(ioc.last_internal_sighting or event.timestamp, event.timestamp)
                self.recalculate(db, ioc)
        return sightings

    @staticmethod
    def _flatten(data: dict, prefix: str = "") -> list[tuple[str, object]]:
        values: list[tuple[str, object]] = []
        for key, value in data.items():
            path = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                values.extend(IOCIntelligenceService._flatten(value, path))
            elif isinstance(value, list):
                values.extend((path, item) for item in value if isinstance(item, (str, int)))
            elif isinstance(value, (str, int)):
                values.append((path, value))
        return values


ioc_intelligence_service = IOCIntelligenceService()
