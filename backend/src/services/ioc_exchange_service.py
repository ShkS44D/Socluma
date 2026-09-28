from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit

from src.services.ioc_intelligence_service import IOCValidationError, normalize_ioc

SUPPORTED_STIX_OBJECTS = {
    "indicator", "observed-data", "sighting", "malware", "threat-actor", "campaign",
    "intrusion-set", "tool", "identity", "relationship", "marking-definition", "note", "report",
}
PATTERN_RE = re.compile(
    r"^\[(?P<object>[a-z0-9-]+):(?P<field>[a-z0-9_.-]+)\s*=\s*'(?P<value>(?:\\'|[^'])+)'\]$",
    re.IGNORECASE,
)
STIX_FIELD_TYPES = {
    ("ipv4-addr", "value"): "ipv4",
    ("ipv6-addr", "value"): "ipv6",
    ("domain-name", "value"): "domain",
    ("url", "value"): "url",
    ("email-addr", "value"): "email",
    ("file", "hashes.md5"): "md5",
    ("file", "hashes.sha-1"): "sha1",
    ("file", "hashes.sha-256"): "sha256",
    ("file", "hashes.sha-512"): "sha512",
}


def parse_stix_bundle(payload: dict, *, max_objects: int = 25_000) -> dict:
    if payload.get("type") != "bundle" or not str(payload.get("id", "")).startswith("bundle--"):
        raise IOCValidationError("STIX_INVALID: expected a STIX 2.1 bundle")
    objects = payload.get("objects")
    if not isinstance(objects, list) or len(objects) > max_objects:
        raise IOCValidationError("STIX_INVALID: object count exceeds the configured limit")
    indicators, unsupported = [], []
    ids = set()
    for item in objects:
        if not isinstance(item, dict) or not item.get("type") or not item.get("id"):
            raise IOCValidationError("STIX_INVALID: every object requires type and id")
        if item["id"] in ids:
            raise IOCValidationError("STIX_INVALID: duplicate object id")
        ids.add(item["id"])
        if item["type"] not in SUPPORTED_STIX_OBJECTS:
            unsupported.append({"id": item["id"], "type": item["type"], "reason": "STIX_OBJECT_UNSUPPORTED"})
            continue
        if item["type"] != "indicator":
            continue
        match = PATTERN_RE.fullmatch(str(item.get("pattern") or "").strip())
        if not match:
            unsupported.append({"id": item["id"], "type": "indicator", "reason": "STIX_PATTERN_UNSUPPORTED"})
            continue
        key = (match.group("object").lower(), match.group("field").lower())
        ioc_type = STIX_FIELD_TYPES.get(key)
        if not ioc_type:
            unsupported.append({"id": item["id"], "type": "indicator", "reason": "STIX_PATTERN_UNSUPPORTED"})
            continue
        normalized = normalize_ioc(ioc_type, match.group("value").replace("\\'", "'"))
        indicators.append({
            "type": normalized.type, "value": normalized.original,
            "normalized_value": normalized.canonical, "stix_id": item["id"],
            "confidence_score": int(item.get("confidence") or 0),
            "valid_from": item.get("valid_from"), "valid_until": item.get("valid_until"),
            "lifecycle_status": "under_review", "tlp": _stix_tlp(item),
            "source_references": list(item.get("external_references") or []),
        })
    return {"bundle_id": payload["id"], "indicators": indicators, "unsupported": unsupported, "object_count": len(objects)}


def export_stix_bundle(iocs: list, *, allow_tlp_red: bool = False) -> dict:
    objects = []
    field_map = {
        "ipv4": ("ipv4-addr", "value"), "ipv6": ("ipv6-addr", "value"),
        "domain": ("domain-name", "value"), "url": ("url", "value"), "email": ("email-addr", "value"),
        "md5": ("file", "hashes.MD5"), "sha1": ("file", "hashes.SHA-1"),
        "sha256": ("file", "hashes.SHA-256"), "sha512": ("file", "hashes.SHA-512"),
    }
    for ioc in sorted(iocs, key=lambda item: item.id):
        if ioc.tlp == "TLP:RED" and not allow_tlp_red:
            raise IOCValidationError("TLP_RESTRICTION_VIOLATION: TLP:RED export requires explicit authorization")
        kind = ioc.type.value if hasattr(ioc.type, "value") else str(ioc.type)
        target = field_map.get(kind)
        if not target:
            continue
        escaped = (ioc.normalized_value or ioc.value).replace("\\", "\\\\").replace("'", "\\'")
        stix_id = ioc.stix_id or f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, ioc.content_hash or ioc.id)}"
        objects.append({
            "type": "indicator", "spec_version": "2.1", "id": stix_id,
            "created": ioc.created_at.isoformat().replace("+00:00", "Z"),
            "modified": ioc.updated_at.isoformat().replace("+00:00", "Z"),
            "pattern_type": "stix", "pattern": f"[{target[0]}:{target[1]} = '{escaped}']",
            "valid_from": (ioc.valid_from or ioc.created_at).isoformat().replace("+00:00", "Z"),
            "confidence": ioc.confidence_score, "labels": sorted(ioc.tags or []),
        })
    manifest = hashlib.sha256(json.dumps(objects, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {
        "type": "bundle", "id": f"bundle--{uuid.uuid5(uuid.NAMESPACE_URL, manifest)}",
        "objects": objects, "x_vigilantai_manifest_sha256": manifest,
    }


def validate_sync_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise IOCValidationError("External intelligence URL must use HTTPS without embedded credentials")
    if parsed.port and parsed.port not in {443, 8443}:
        raise IOCValidationError("External intelligence URL uses an unapproved port")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(parsed.hostname, parsed.port or 443)}
    except socket.gaierror as exc:
        raise IOCValidationError("External intelligence hostname could not be resolved") from exc
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            raise IOCValidationError("External intelligence URL resolves to a blocked destination")
    return url


def _stix_tlp(item: dict) -> str:
    markings = " ".join(item.get("object_marking_refs") or []).lower()
    for name in ("red", "amber+strict", "amber", "green", "clear"):
        if name in markings:
            return f"TLP:{name.upper()}"
    return "TLP:AMBER"
