from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from src.models.sqlalchemy import EntityRelationship, EventEntity, SearchEntity, SecurityEvent
from src.utils.datetime_utils import ensure_utc


class EntityInvestigationService:
    MAX_ENTITIES_PER_EVENT = 50
    EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}$")
    HASH = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")
    DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")

    PATHS = {
        "user": ("actor.user", "user.name", "username", "user", "account_name"),
        "host": ("device.hostname", "host.name", "hostname", "host", "computer_name"),
        "source_ip": ("network.src_ip", "source.ip", "source_ip", "src_ip", "src"),
        "destination_ip": ("network.dst_ip", "destination.ip", "destination_ip", "dst_ip", "dst"),
        "process": ("process.name", "process_name", "image", "Image", "process"),
        "file": ("file.path", "file.name", "file_path", "path", "filename"),
        "hash": ("file.hash.sha256", "file.hash.sha1", "file.hash.md5", "sha256", "sha1", "md5", "hash"),
        "domain": ("domain", "dns.question.name", "domain_name"),
        "url": ("url", "http.url", "request_url"),
        "email": ("email", "user.email"),
    }

    def extract_event(self, db: Session, event: SecurityEvent) -> list[SearchEntity]:
        payload = {**(event.raw_event or {}), **(event.normalized_event or {})}
        found: dict[tuple[str, str], dict[str, Any]] = {}
        for role, paths in self.PATHS.items():
            entity_type = role.removeprefix("source_").removeprefix("destination_")
            for path in paths:
                value = self._get(payload, path)
                for scalar in value if isinstance(value, list) else [value]:
                    normalized = self._normalize(entity_type, scalar)
                    if normalized:
                        found[(entity_type, normalized)] = {"display": str(scalar)[:1024], "role": role, "path": path}
                    if len(found) >= self.MAX_ENTITIES_PER_EVENT:
                        break
        observed = ensure_utc(event.timestamp)
        entities: list[SearchEntity] = []
        by_role: dict[str, SearchEntity] = {}
        for (entity_type, normalized), metadata in found.items():
            entity = db.query(SearchEntity).filter(
                SearchEntity.tenant_id == event.tenant_id,
                SearchEntity.entity_type == entity_type,
                SearchEntity.normalized_value == normalized,
            ).first()
            if not entity:
                entity = SearchEntity(
                    tenant_id=event.tenant_id, entity_type=entity_type,
                    normalized_value=normalized, display_value=metadata["display"],
                    first_seen_at=observed, last_seen_at=observed,
                    extraction_source=f"event:{metadata['path']}",
                )
                db.add(entity)
                db.flush()
            link = db.query(EventEntity).filter(
                EventEntity.event_id == event.id, EventEntity.entity_id == entity.id,
                EventEntity.role == metadata["role"],
            ).first()
            if not link:
                if entity.sighting_count:
                    entity.sighting_count += 1
                else:
                    entity.sighting_count = 1
                entity.first_seen_at = min(ensure_utc(entity.first_seen_at), observed)
                entity.last_seen_at = max(ensure_utc(entity.last_seen_at), observed)
                db.add(EventEntity(
                    tenant_id=event.tenant_id, event_id=event.id, entity_id=entity.id,
                    role=metadata["role"], evidence={"field": metadata["path"]}, observed_at=observed,
                ))
            entities.append(entity)
            by_role[metadata["role"]] = entity
        self._relationships(db, event, by_role, observed)
        db.flush()
        return entities

    def graph(self, db: Session, tenant_id: str, entity_id: str, depth: int, max_nodes: int, max_edges: int):
        root = db.query(SearchEntity).filter(SearchEntity.id == entity_id, SearchEntity.tenant_id == tenant_id).first()
        if not root:
            raise ValueError("ENTITY_NOT_FOUND")
        nodes = {root.id: root}
        edges: list[EntityRelationship] = []
        frontier = {root.id}
        for _ in range(depth):
            if not frontier or len(nodes) >= max_nodes or len(edges) >= max_edges:
                break
            rows = db.query(EntityRelationship).filter(
                EntityRelationship.tenant_id == tenant_id,
                ((EntityRelationship.source_entity_id.in_(frontier)) | (EntityRelationship.target_entity_id.in_(frontier))),
            ).limit(max_edges - len(edges)).all()
            new_ids = set()
            for edge in rows:
                if edge.id not in {item.id for item in edges}:
                    edges.append(edge)
                new_ids.update((edge.source_entity_id, edge.target_entity_id))
            new_ids -= set(nodes)
            if not new_ids:
                break
            for entity in db.query(SearchEntity).filter(
                SearchEntity.tenant_id == tenant_id, SearchEntity.id.in_(list(new_ids)),
            ).limit(max_nodes - len(nodes)).all():
                nodes[entity.id] = entity
            frontier = set(nodes).intersection(new_ids)
        return {
            "nodes": [{"id": item.id, "type": item.entity_type, "label": item.display_value,
                       "first_seen_at": item.first_seen_at, "last_seen_at": item.last_seen_at} for item in nodes.values()],
            "edges": [{"id": edge.id, "source": edge.source_entity_id, "target": edge.target_entity_id,
                       "type": edge.relationship_type, "observed": edge.observed,
                       "evidence_event_id": edge.evidence_event_id, "first_seen_at": edge.first_seen_at,
                       "last_seen_at": edge.last_seen_at} for edge in edges],
            "truncated": len(nodes) >= max_nodes or len(edges) >= max_edges,
        }

    def _relationships(self, db, event, roles, observed):
        definitions = (
            ("user", "host", "user_logged_into_host"),
            ("user", "process", "user_executed_process"),
            ("host", "source_ip", "host_connected_to_ip"),
            ("host", "destination_ip", "host_connected_to_ip"),
            ("process", "file", "process_accessed_file"),
            ("domain", "destination_ip", "domain_resolved_to_ip"),
        )
        for source_role, target_role, relationship_type in definitions:
            source, target = roles.get(source_role), roles.get(target_role)
            if not source or not target or source.id == target.id:
                continue
            edge = db.query(EntityRelationship).filter(
                EntityRelationship.tenant_id == event.tenant_id,
                EntityRelationship.source_entity_id == source.id,
                EntityRelationship.target_entity_id == target.id,
                EntityRelationship.relationship_type == relationship_type,
            ).first()
            if edge:
                edge.last_seen_at = max(ensure_utc(edge.last_seen_at), observed)
                edge.sighting_count += 1
            else:
                db.add(EntityRelationship(
                    tenant_id=event.tenant_id, source_entity_id=source.id, target_entity_id=target.id,
                    relationship_type=relationship_type, observed=True, first_seen_at=observed,
                    last_seen_at=observed, evidence_event_id=event.id,
                ))

    @staticmethod
    def _get(value: dict[str, Any], path: str):
        current: Any = value
        for part in path.split("."):
            if not isinstance(current, dict) or part not in current:
                return None
            current = current[part]
        return current

    def _normalize(self, entity_type: str, value: Any) -> str | None:
        if value is None or isinstance(value, (dict, list, bool)):
            return None
        text = str(value).strip()
        if not text or len(text) > 2048:
            return None
        if entity_type == "ip":
            try:
                return str(ipaddress.ip_address(text))
            except ValueError:
                return None
        if entity_type == "hash":
            return text.lower() if self.HASH.fullmatch(text) else None
        if entity_type == "domain":
            candidate = text.lower().rstrip(".")
            return candidate if self.DOMAIN.fullmatch(candidate) else None
        if entity_type == "url":
            parsed = urlparse(text)
            return text[:2048] if parsed.scheme in {"http", "https"} and parsed.hostname else None
        if entity_type == "email":
            return text.lower() if self.EMAIL.fullmatch(text) else None
        if entity_type in {"user", "host", "process", "file"}:
            return text.casefold()[:1024] if 1 <= len(text) <= 1024 else None
        return None


entity_investigation_service = EntityInvestigationService()
