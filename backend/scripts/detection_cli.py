"""Offline detection-as-code validation and test utility.

This tool never connects to the application database and never publishes rules.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.core.config import get_settings
from src.services.detection_lifecycle_service import detection_lifecycle_service


def _read(path: Path) -> bytes:
    data = path.read_bytes()
    if len(data) > get_settings().DETECTION_MAX_RULE_BYTES:
        raise ValueError("DETECTION_COMPLEXITY_EXCEEDED: file exceeds configured size")
    return data


def _documents(path: Path) -> list[dict]:
    raw = _read(path)
    if path.suffix.casefold() == ".json":
        value = json.loads(raw)
        return value if isinstance(value, list) else [value]
    return [item for item in yaml.safe_load_all(raw) if item is not None]


def _definition(document: dict) -> tuple[dict, str | None]:
    if "definition" in document:
        return document["definition"], document.get("sigma")
    if "detection" in document:
        return document, yaml.safe_dump(document, sort_keys=False)
    return document, None


def validate(paths: list[Path]) -> int:
    reports = []
    failed = False
    for path in paths:
        for index, document in enumerate(_documents(path), 1):
            definition, sigma = _definition(document)
            report = detection_lifecycle_service.validate(
                definition, sigma_content=sigma
            )
            failed = failed or not report["valid"]
            reports.append({"file": path.as_posix(), "document": index, **report})
    print(json.dumps({"valid": not failed, "reports": reports}, sort_keys=True, default=str))
    return 1 if failed else 0


def test(rule_path: Path, events_path: Path) -> int:
    documents = _documents(rule_path)
    if len(documents) != 1:
        raise ValueError("Test accepts exactly one rule document")
    definition, sigma = _definition(documents[0])
    report = detection_lifecycle_service.validate(definition, sigma_content=sigma)
    if not report["valid"]:
        print(json.dumps(report, sort_keys=True))
        return 1
    events = []
    for index, item in enumerate(_documents(events_path)):
        events.append(SimpleNamespace(
            id=item.get("id", f"event-{index}"),
            timestamp=(
                datetime.fromisoformat(str(item["timestamp"]).replace("Z", "+00:00"))
                if item.get("timestamp")
                else datetime(1970, 1, 1, tzinfo=timezone.utc)
            ),
            source=item.get("source", "offline-test"),
            severity=item.get("severity", "medium"),
            normalized_event=item.get("normalized_event") or item,
            raw_event=item.get("raw_event") or {},
        ))
    result = detection_lifecycle_service.evaluate_events(definition, events)
    result.pop("duration_ms", None)
    print(json.dumps(result, sort_keys=True, default=str))
    return 0


def manifest(paths: list[Path]) -> int:
    files = []
    for path in sorted(paths, key=lambda item: item.as_posix()):
        data = _read(path)
        files.append({
            "path": path.as_posix(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
        })
    canonical = json.dumps(files, sort_keys=True, separators=(",", ":"))
    print(json.dumps({
        "schema_version": "1.0",
        "files": files,
        "content_hash": hashlib.sha256(canonical.encode()).hexdigest(),
    }, sort_keys=True))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate and test VigilantAI detection content")
    commands = parser.add_subparsers(dest="command", required=True)
    validation = commands.add_parser("validate")
    validation.add_argument("files", nargs="+", type=Path)
    testing = commands.add_parser("test")
    testing.add_argument("rule", type=Path)
    testing.add_argument("events", type=Path)
    manifests = commands.add_parser("manifest")
    manifests.add_argument("files", nargs="+", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "validate":
            return validate(args.files)
        if args.command == "test":
            return test(args.rule, args.events)
        return manifest(args.files)
    except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as exc:
        print(json.dumps({"valid": False, "error": type(exc).__name__, "message": str(exc)}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
