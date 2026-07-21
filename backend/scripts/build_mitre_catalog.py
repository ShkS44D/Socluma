"""Build TriageOps' pinned catalog subset from an official Enterprise ATT&CK STIX bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
]


def external_id(obj: dict) -> str | None:
    return next((ref.get("external_id") for ref in obj.get("external_references", []) if ref.get("source_name") == "mitre-attack"), None)


def build(source: Path, output: Path, version: str) -> None:
    source_bytes = source.read_bytes()
    bundle = json.loads(source_bytes.decode("utf-8"))
    objects = bundle["objects"]
    project_root = Path(__file__).resolve().parents[2]
    referenced: set[str] = set()
    for path in (
        project_root / "backend/src/services/default_detection_rules.py",
        project_root / "backend/scripts/seed_analyst_pilot.py",
        project_root / "backend/src/api/openapi_examples.py",
    ):
        referenced.update(re.findall(r"T\d{4}(?:\.\d{3})?", path.read_text(encoding="utf-8")))
    attack_patterns = {obj["id"]: obj for obj in objects if obj.get("type") == "attack-pattern" and external_id(obj)}
    by_external = {external_id(obj): obj for obj in attack_patterns.values()}
    tactic_metadata = {
        obj["x_mitre_shortname"]: {
            "id": external_id(obj),
            "name": obj["name"],
            "order": TACTIC_ORDER.index(obj["name"]),
        }
        for obj in objects
        if obj.get("type") == "x-mitre-tactic"
        and external_id(obj)
        and obj.get("x_mitre_shortname")
        and obj.get("name") in TACTIC_ORDER
    }
    parent_by_child = {}
    for obj in objects:
        if obj.get("type") == "relationship" and obj.get("relationship_type") == "subtechnique-of":
            parent_by_child[obj["source_ref"]] = obj["target_ref"]
    referenced.update(item.split(".", 1)[0] for item in tuple(referenced) if "." in item)
    missing = sorted(referenced - set(by_external))
    if missing:
        raise SystemExit(f"Official ATT&CK bundle does not contain referenced IDs: {', '.join(missing)}")
    records = []
    for technique_id in sorted(referenced):
        obj = by_external[technique_id]
        parent_obj = attack_patterns.get(parent_by_child.get(obj["id"], ""))
        parent_id = external_id(parent_obj) if parent_obj else technique_id
        parent_name = parent_obj["name"] if parent_obj else obj["name"]
        tactics = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") != "mitre-attack":
                continue
            metadata = tactic_metadata.get(phase["phase_name"])
            if metadata:
                tactics.append(metadata)
        tactics = sorted({item["name"]: item for item in tactics}.values(), key=lambda item: item["order"])
        if not tactics:
            tactics = [{"id": "unresolved", "name": "Unknown", "order": len(TACTIC_ORDER)}]
        ext = next(ref for ref in obj["external_references"] if ref.get("source_name") == "mitre-attack")
        records.append({
            "technique_id": technique_id, "name": obj["name"], "description": obj.get("description"),
            "tactic": tactics[0]["name"], "tactic_id": tactics[0]["id"], "tactic_order": tactics[0]["order"], "tactics": tactics,
            "parent_technique_id": parent_id, "parent_technique_name": parent_name,
            "sub_technique_id": technique_id if obj.get("x_mitre_is_subtechnique") else None,
            "sub_technique_name": obj["name"] if obj.get("x_mitre_is_subtechnique") else None,
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")), "is_revoked": bool(obj.get("revoked")),
            "is_deprecated": bool(obj.get("x_mitre_deprecated")), "catalog_version": version,
            "catalog_source": f"MITRE ATT&CK Enterprise STIX {version}", "external_url": ext.get("url"),
        })
    payload = {
        "catalog_version": version,
        "source": "https://github.com/mitre-attack/attack-stix-data",
        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "techniques": records,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--version", default="v18.1")
    args = parser.parse_args()
    build(args.source, args.output, args.version)
