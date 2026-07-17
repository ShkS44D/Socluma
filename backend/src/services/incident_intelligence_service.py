from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import ipaddress
import re
from typing import Any, Iterable, Sequence
from urllib.parse import urlsplit

from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from src.models.sqlalchemy import (
    Alert,
    AuditLog,
    DetectionMatch,
    DetectionRule,
    EvidenceType,
    Incident,
    IncidentAlert,
    IncidentComment,
    IncidentEntity,
    IncidentEvidence,
    IncidentIOC,
    IOC,
    InvestigationNote,
    SecurityEvent,
    Severity,
)
from src.utils.datetime_utils import ensure_utc, utc_isoformat


class IncidentIntelligenceService:
    """Builds auditable incident provenance from stored tenant-scoped facts."""

    _SEVERITY_WEIGHT = {
        Severity.CRITICAL: 40.0,
        Severity.HIGH: 30.0,
        Severity.MEDIUM: 20.0,
        Severity.LOW: 10.0,
    }
    _ENTITY_KEYS: dict[str, tuple[str, ...]] = {
        "user": ("user", "username", "user_name", "target_user", "subject_user_name"),
        "host": ("hostname", "host", "computer", "computer_name", "device"),
        "ip_address": ("ip", "source_ip", "src_ip", "destination_ip", "dst_ip", "client_ip", "remote_ip"),
        "process": ("process", "process_name", "image", "Image", "parent_process", "ParentImage"),
        "file": ("file", "file_name", "file_path", "path"),
        "file_hash": ("hash", "file_hash", "sha256", "sha1", "md5"),
        "domain": ("domain", "destination_domain", "query_name", "dns_query"),
        "url": ("url", "uri", "request_url"),
        "email_address": ("email", "email_address", "mail_from", "recipient"),
        "cloud_resource": ("resource_id", "cloud_resource", "instance_id", "subscription_id"),
        "collector": ("collector_id",),
        "log_source": ("log_source", "source"),
    }

    def capture_provenance(
        self,
        db: Session,
        incident: Incident,
        alerts: Sequence[Alert],
        *,
        correlation_score: float,
        correlation_reasons: Sequence[str],
        risk: dict[str, Any],
        created: bool,
        triggering_alert_id: str | None = None,
    ) -> None:
        ordered_alerts = sorted(
            {alert.id: alert for alert in alerts}.values(),
            key=lambda item: (self._observed_at(item), item.id),
        )
        if not ordered_alerts:
            return

        links = {
            link.alert_id: link
            for link in db.query(IncidentAlert)
            .filter(IncidentAlert.incident_id == incident.id)
            .all()
        }
        existing_primary = next((link for link in links.values() if link.is_primary), None)
        primary_alert = existing_primary.alert if existing_primary and existing_primary.alert else ordered_alerts[0]
        if created and triggering_alert_id:
            primary_alert = next(
                (item for item in ordered_alerts if item.id == triggering_alert_id),
                primary_alert,
            )
        if incident.primary_alert_id and incident.primary_alert_id in {item.id for item in ordered_alerts}:
            primary_alert = next(item for item in ordered_alerts if item.id == incident.primary_alert_id)

        all_alerts = sorted(
            {link.alert_id: link.alert for link in links.values() if link.alert}.values(),
            key=lambda item: (self._observed_at(item), item.id),
        )
        if not all_alerts:
            all_alerts = ordered_alerts
        if primary_alert.id not in {item.id for item in all_alerts}:
            all_alerts.insert(0, primary_alert)

        primary_time = self._observed_at(primary_alert)
        total_weight = sum(self._alert_weight(item) for item in all_alerts) or 1.0
        reason_text = "; ".join(dict.fromkeys(reason for reason in correlation_reasons if reason))

        total_risk = round(float(risk.get("risk_score") or incident.risk_score or 0), 2)
        allocated_risk = 0.0
        for index, alert in enumerate(all_alerts, start=1):
            link = links.get(alert.id)
            if link is None:
                continue
            is_primary = alert.id == primary_alert.id
            entities = self.extract_alert_entities(alert)
            link.is_primary = is_primary
            link.sequence_order = index
            link.attachment_reason = (
                "This alert created the incident."
                if is_primary
                else reason_text or "No recorded correlation reason is available for this alert."
            )
            contribution = round(total_risk * self._alert_weight(alert) / total_weight, 2)
            if index == len(all_alerts):
                contribution = round(total_risk - allocated_risk, 2)
            link.risk_contribution = contribution
            allocated_risk = round(allocated_risk + contribution, 2)
            link.matching_entities = [
                {"type": entity["type"], "value": entity["value"]}
                for entity in entities
            ]
            link.matching_indicators = [
                {"type": entity["type"], "value": entity["value"]}
                for entity in entities
                if entity["type"] in {"ip_address", "domain", "url", "file_hash"}
            ]
            link.time_delta_seconds = abs((self._observed_at(alert) - primary_time).total_seconds())
            db.add(link)

        incident.primary_alert_id = primary_alert.id
        incident.creation_source = "detection_engine"
        incident.provenance_status = "recorded"
        incident.creation_reason = incident.creation_reason or self._creation_reason(primary_alert, reason_text)
        if reason_text:
            incident.correlation_rule_name = incident.correlation_rule_name or "Built-in alert correlation"
            incident.correlation_key = self._correlation_key(all_alerts)
        incident.correlation_score = max(float(incident.correlation_score or 0), float(correlation_score or 0))
        observed_times = [self._observed_at(alert) for alert in all_alerts]
        incident.first_seen_at = min(observed_times)
        incident.last_seen_at = max(observed_times)
        incident.correlation_window_start = min(observed_times)
        incident.correlation_window_end = max(observed_times)
        incident.risk_score_breakdown = risk.get("breakdown") or incident.risk_score_breakdown or {
            "total": float(risk.get("risk_score") or incident.risk_score or 0),
            "reason": risk.get("reason"),
        }
        incident.severity_reason = risk.get("reason") or incident.severity_reason
        incident.attack_summary = self._attack_summary(primary_alert, all_alerts)
        if created and not incident.status_reason:
            incident.status_reason = "New incident awaiting analyst triage."
        db.add(incident)

        entity_cache = {
            (item.entity_type, item.normalized_value): item
            for item in db.query(IncidentEntity)
            .filter(IncidentEntity.tenant_id == incident.tenant_id, IncidentEntity.incident_id == incident.id)
            .all()
        }
        for alert in all_alerts:
            self._sync_entities(db, incident, alert, entity_cache)

    def build_explanation(
        self,
        db: Session,
        tenant_id: str,
        incident_id: str,
        *,
        alert_page: int = 1,
        alert_limit: int = 20,
        event_limit: int = 30,
        entity_limit: int = 50,
        ioc_limit: int = 20,
        evidence_limit: int = 20,
        timeline_limit: int = 50,
    ) -> dict[str, Any]:
        incident = (
            db.query(Incident)
            .filter(Incident.id == incident_id, Incident.tenant_id == tenant_id)
            .first()
        )
        if not incident:
            raise ValueError("Incident not found")

        tenant_link_query = (
            db.query(IncidentAlert)
            .join(Incident, IncidentAlert.incident_id == Incident.id)
            .filter(Incident.tenant_id == tenant_id, IncidentAlert.incident_id == incident_id)
        )
        alert_total = tenant_link_query.count()
        links = (
            tenant_link_query
            .options(
                joinedload(IncidentAlert.alert).joinedload(Alert.detection_rule),
                joinedload(IncidentAlert.alert).joinedload(Alert.event),
            )
            .order_by(IncidentAlert.sequence_order.asc(), IncidentAlert.created_at.asc())
            .offset((alert_page - 1) * alert_limit)
            .limit(alert_limit)
            .all()
        )
        links = [link for link in links if link.alert]
        primary_link = next((link for link in links if link.is_primary), None)
        if primary_link is None and links:
            primary_link = next((link for link in links if link.alert_id == incident.primary_alert_id), links[0])

        event_by_id: dict[str, SecurityEvent] = {}
        for link in links:
            if link.alert.event and len(event_by_id) < event_limit:
                event_by_id[link.alert.event.id] = link.alert.event

        event_count = (
            db.query(func.count(func.distinct(Alert.event_id)))
            .join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
            .filter(IncidentAlert.incident_id == incident_id, Alert.tenant_id == tenant_id, Alert.event_id.isnot(None))
            .scalar_subquery()
        )
        entity_count = db.query(func.count(IncidentEntity.id)).filter(
            IncidentEntity.tenant_id == tenant_id,
            IncidentEntity.incident_id == incident_id,
        ).scalar_subquery()
        ioc_count = db.query(func.count(IncidentIOC.id)).filter(
            IncidentIOC.tenant_id == tenant_id,
            IncidentIOC.incident_id == incident_id,
        ).scalar_subquery()
        evidence_count = (
            db.query(func.count(IncidentEvidence.id))
            .join(Incident, IncidentEvidence.incident_id == Incident.id)
            .filter(Incident.tenant_id == tenant_id, IncidentEvidence.incident_id == incident_id)
            .scalar_subquery()
        )
        event_total, entity_total, ioc_total, evidence_total = db.query(
            event_count, entity_count, ioc_count, evidence_count
        ).one()
        event_total = int(event_total or 0)
        entity_total = int(entity_total or 0)
        ioc_total = int(ioc_total or 0)
        evidence_total = int(evidence_total or 0)
        entities = (
            db.query(IncidentEntity)
            .filter(IncidentEntity.tenant_id == tenant_id, IncidentEntity.incident_id == incident_id)
            .order_by(IncidentEntity.risk_contribution.desc(), IncidentEntity.entity_type.asc())
            .limit(entity_limit)
            .all()
        )
        ioc_links = (
            db.query(IncidentIOC)
            .options(joinedload(IncidentIOC.ioc).joinedload(IOC.enrichments))
            .filter(IncidentIOC.tenant_id == tenant_id, IncidentIOC.incident_id == incident_id)
            .limit(ioc_limit)
            .all()
        )
        evidence = (
            db.query(IncidentEvidence)
            .join(Incident, IncidentEvidence.incident_id == Incident.id)
            .filter(Incident.tenant_id == tenant_id, IncidentEvidence.incident_id == incident_id)
            .order_by(IncidentEvidence.created_at.desc())
            .limit(evidence_limit)
            .all()
        )
        comments = (
            db.query(IncidentComment)
            .filter(IncidentComment.tenant_id == tenant_id, IncidentComment.incident_id == incident_id)
            .order_by(IncidentComment.created_at.asc())
            .limit(max(1, timeline_limit // 2))
            .all()
        )
        notes = (
            db.query(InvestigationNote)
            .join(Incident, InvestigationNote.incident_id == Incident.id)
            .filter(Incident.tenant_id == tenant_id, InvestigationNote.incident_id == incident_id)
            .order_by(InvestigationNote.created_at.asc())
            .limit(max(1, timeline_limit // 2))
            .all()
        )

        primary_alert = self._alert_reference(primary_link) if primary_link else None
        if primary_alert is not None:
            primary_alert["is_primary"] = True
        correlated = [self._alert_reference(link) for link in links if link is not primary_link]
        source_events = [self._event_reference(event) for event in event_by_id.values()]
        detection_matches = self._detection_references(links)
        entity_rows = [self._entity_reference(entity) for entity in entities]
        derived_fields: list[str] = []
        if not entity_rows:
            entity_rows = self._derived_entity_references(links)
            if entity_rows:
                derived_fields.append("affected_entities")
                entity_total = len(entity_rows)
        ioc_rows = [self._ioc_reference(link.ioc) for link in ioc_links if link.ioc]
        evidence_rows = [self._evidence_reference(item) for item in evidence]
        complete_timeline = self._timeline(incident, links, event_by_id.values(), comments, notes)
        timeline_total = len(complete_timeline)
        timeline = complete_timeline[:timeline_limit]
        mitre = self._mitre(incident, links)
        risk_breakdown = incident.risk_score_breakdown or {
            "total": float(incident.risk_score or 0),
            "reason": incident.severity_reason or "Stored incident risk score.",
        }
        references = self._evidence_references(
            incident,
            alerts=[item for item in [primary_alert, *correlated] if item],
            events=source_events,
            detection_matches=detection_matches,
            entities=entity_rows,
            iocs=ioc_rows,
            evidence=evidence_rows,
        )
        references = self.validate_evidence_references(db, tenant_id, incident_id, references)

        is_legacy = (incident.provenance_status or "legacy_derived") == "legacy_derived"
        legacy_caveat = (
            "The incident predates detailed correlation tracking, so the exact historical correlation reason is unavailable."
        )
        correlation_reasons = [] if is_legacy else list(
            dict.fromkeys(link.correlation_reason for link in links if link.correlation_reason)
        )
        if is_legacy:
            derived_fields.extend(["primary_alert", "first_seen_at", "last_seen_at"])
        limitations = self._limitations(links, event_by_id, entity_rows)
        if alert_total > len(links) or event_total > len(source_events) or entity_total > len(entity_rows):
            limitations.append("Large collections were bounded; the response contains the most relevant first page.")
        if is_legacy:
            limitations.insert(0, legacy_caveat)

        return {
            "incident_id": incident.id,
            "origin": {
                "creation_source": incident.creation_source or "manual",
                "provenance_status": incident.provenance_status or "legacy_derived",
                "derived_fields": list(dict.fromkeys(derived_fields)),
                "creation_reason": incident.creation_reason or (
                    legacy_caveat if is_legacy else self._legacy_creation_reason(primary_link)
                ),
                "created_at": incident.created_at,
                "first_seen_at": incident.first_seen_at or (timeline[0]["timestamp"] if timeline else incident.created_at),
                "last_seen_at": incident.last_seen_at or (timeline[-1]["timestamp"] if timeline else incident.updated_at),
                "status_reason": incident.status_reason,
            },
            "primary_alert": primary_alert,
            "correlated_alerts": correlated,
            "source_events": source_events,
            "detection_matches": detection_matches,
            "correlation": {
                "rule_id": incident.correlation_rule_id,
                "rule_name": incident.correlation_rule_name or (
                    "Unavailable" if is_legacy else "No correlation rule required"
                ),
                "key": incident.correlation_key,
                "score": float(incident.correlation_score or 0),
                "window_start": incident.correlation_window_start,
                "window_end": incident.correlation_window_end,
                "reasons": correlation_reasons,
            },
            "timeline_summary": timeline,
            "affected_entities": entity_rows,
            "ioc_summary": ioc_rows,
            "mitre_attack_mapping": mitre,
            "risk_score_breakdown": risk_breakdown,
            "severity_reason": incident.severity_reason,
            "attack_summary": incident.attack_summary or incident.description,
            "evidence_summary": {
                "source_alert_count": alert_total,
                "source_event_count": event_total,
                "affected_entity_count": entity_total,
                "manual_evidence": evidence_rows,
                "references": references,
            },
            "recommended_investigation_questions": self._recommended_questions(entity_rows, ioc_rows, mitre),
            "limitations": limitations,
            "collection_metadata": {
                "alerts": self._page_metadata(alert_total, len(links), alert_page, alert_limit),
                "events": self._page_metadata(event_total, len(source_events), 1, event_limit),
                "entities": self._page_metadata(entity_total, len(entity_rows), 1, entity_limit),
                "iocs": self._page_metadata(ioc_total, len(ioc_rows), 1, ioc_limit),
                "evidence": self._page_metadata(evidence_total, len(evidence_rows), 1, evidence_limit),
                "timeline": self._page_metadata(timeline_total, len(timeline), 1, timeline_limit),
                "references": self._page_metadata(len(references), len(references), 1, max(1, len(references))),
            },
        }

    def _page_metadata(self, total: int, included: int, page: int, page_size: int) -> dict[str, Any]:
        return {
            "total": int(total),
            "included": int(included),
            "page": page,
            "page_size": page_size,
            "has_more": page * page_size < total,
        }

    def extract_alert_entities(self, alert: Alert) -> list[dict[str, Any]]:
        payloads = [alert.raw_data or {}, alert.ocsf_data or {}]
        if alert.event:
            payloads.extend([alert.event.normalized_event or {}, alert.event.raw_event or {}])
        found: dict[tuple[str, str], dict[str, Any]] = {}
        for entity_type, keys in self._ENTITY_KEYS.items():
            for payload in payloads:
                for key, value in self._walk(payload):
                    leaf = key.rsplit(".", 1)[-1]
                    if leaf not in keys or not self._usable(value):
                        continue
                    for scalar in self._scalars(value):
                        normalized = self._normalize(entity_type, scalar)
                        if not normalized:
                            continue
                        found[(entity_type, normalized)] = {
                            "type": entity_type,
                            "value": str(scalar)[:2048],
                            "normalized_value": normalized[:2048],
                            "role": self._role_from_path(key),
                        }
        if alert.detection_rule:
            found[("detection_rule", alert.detection_rule.id)] = {
                "type": "detection_rule",
                "value": alert.detection_rule.name,
                "normalized_value": alert.detection_rule.id,
                "role": "matched_rule",
            }
        if alert.event and alert.event.source:
            normalized = alert.event.source.strip().lower()
            found[("log_source", normalized)] = {
                "type": "log_source",
                "value": alert.event.source,
                "normalized_value": normalized,
                "role": "telemetry_source",
            }
        return list(found.values())

    def _sync_entities(
        self,
        db: Session,
        incident: Incident,
        alert: Alert,
        existing: dict[tuple[str, str], IncidentEntity],
    ) -> None:
        observed_at = self._observed_at(alert)
        for data in self.extract_alert_entities(alert):
            key = (data["type"], data["normalized_value"])
            entity = existing.get(key)
            if entity is None:
                entity = IncidentEntity(
                    tenant_id=incident.tenant_id,
                    incident_id=incident.id,
                    entity_type=data["type"],
                    value=data["value"],
                    normalized_value=data["normalized_value"],
                    role=data.get("role"),
                    first_seen_at=observed_at,
                    last_seen_at=observed_at,
                    source_event_id=alert.event_id,
                    source_alert_id=alert.id,
                    confidence=1.0,
                    risk_contribution=self._alert_weight(alert),
                )
                db.add(entity)
                db.flush()
                existing[key] = entity
            else:
                entity.first_seen_at = min(ensure_utc(entity.first_seen_at or observed_at), observed_at)
                entity.last_seen_at = max(ensure_utc(entity.last_seen_at or observed_at), observed_at)
                entity.risk_contribution = max(float(entity.risk_contribution or 0), self._alert_weight(alert))
                db.add(entity)
            self._sync_indicator_evidence(db, incident, alert, entity)

    def _sync_indicator_evidence(
        self, db: Session, incident: Incident, alert: Alert, entity: IncidentEntity
    ) -> None:
        evidence_type = {
            "ip_address": EvidenceType.IP,
            "domain": EvidenceType.DOMAIN,
            "file_hash": EvidenceType.HASH,
            "file": EvidenceType.FILE,
            "url": EvidenceType.URL,
        }.get(entity.entity_type)
        if evidence_type is None:
            return
        exists = db.query(IncidentEvidence.id).filter(
            IncidentEvidence.incident_id == incident.id,
            IncidentEvidence.source_alert_id == alert.id,
            IncidentEvidence.type == evidence_type,
            IncidentEvidence.value == entity.value,
        ).first()
        if exists:
            return
        db.add(IncidentEvidence(
            tenant_id=incident.tenant_id,
            incident_id=incident.id,
            user_id=None,
            source_event_id=alert.event_id,
            source_alert_id=alert.id,
            source_entity_id=entity.id,
            type=evidence_type,
            value=entity.value[:1024],
            description=f"Automatically extracted from {entity.role or 'incident telemetry'}.",
            confidence=entity.confidence,
            risk_contribution=entity.risk_contribution,
            evidence_metadata={"automated": True, "entity_type": entity.entity_type},
        ))

    def _alert_reference(self, link: IncidentAlert) -> dict[str, Any]:
        alert = link.alert
        rule = alert.detection_rule
        return {
            "id": alert.id,
            "event_id": alert.event_id,
            "detection_rule_id": alert.detection_rule_id,
            "detection_rule_name": rule.name if rule else None,
            "severity": self._value(alert.severity),
            "status": self._value(alert.status),
            "created_at": alert.created_at,
            "why_matched": alert.why_matched,
            "matched_condition": alert.matched_condition,
            "is_primary": bool(link.is_primary),
            "attachment_reason": link.attachment_reason or link.correlation_reason,
            "correlation_reason": link.correlation_reason,
            "correlation_score": float(link.correlation_score or 0),
            "sequence_order": int(link.sequence_order or 0),
            "risk_contribution": float(link.risk_contribution or 0),
            "matching_entities": link.matching_entities or [],
            "matching_indicators": link.matching_indicators or [],
            "time_delta_seconds": float(link.time_delta_seconds or 0),
        }

    def _event_reference(self, event: SecurityEvent) -> dict[str, Any]:
        return {
            "id": event.id,
            "source": event.source,
            "event_type": self._value(event.event_type),
            "severity": self._value(event.severity),
            "timestamp": event.timestamp,
            "created_at": event.created_at,
            "processed": bool(event.processed),
        }

    def _detection_references(self, links: Sequence[IncidentAlert]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        seen: set[tuple[str | None, str]] = set()
        for link in links:
            alert = link.alert
            rule = alert.detection_rule
            key = (alert.detection_rule_id, alert.id)
            if key in seen:
                continue
            seen.add(key)
            results.append({
                "alert_id": alert.id,
                "event_id": alert.event_id,
                "rule_id": alert.detection_rule_id,
                "rule_name": rule.name if rule else None,
                "mitre_technique_id": rule.mitre_technique_id if rule else None,
                "matched_condition": alert.matched_condition,
                "why_matched": alert.why_matched,
                "severity": self._value(alert.severity),
            })
        return results

    def _entity_reference(self, entity: IncidentEntity) -> dict[str, Any]:
        return {
            "id": entity.id,
            "type": entity.entity_type,
            "value": entity.value,
            "normalized_value": entity.normalized_value,
            "role": entity.role,
            "first_seen_at": entity.first_seen_at,
            "last_seen_at": entity.last_seen_at,
            "source_event_id": entity.source_event_id,
            "source_alert_id": entity.source_alert_id,
            "confidence": entity.confidence,
            "risk_contribution": entity.risk_contribution,
        }

    def _derived_entity_references(self, links: Sequence[IncidentAlert]) -> list[dict[str, Any]]:
        """Expose evidence-backed entities for incidents created before entity persistence."""
        derived: dict[tuple[str, str], dict[str, Any]] = {}
        for link in links:
            for entity in self.extract_alert_entities(link.alert):
                key = (entity["type"], entity["normalized_value"])
                if key in derived:
                    continue
                stable_id = hashlib.sha256(f"{key[0]}:{key[1]}".encode("utf-8")).hexdigest()[:36]
                derived[key] = {
                    "id": f"derived-{stable_id}",
                    "type": entity["type"],
                    "value": entity["value"],
                    "normalized_value": entity["normalized_value"],
                    "role": entity.get("role"),
                    "first_seen_at": link.alert.event.timestamp if link.alert.event else link.alert.created_at,
                    "last_seen_at": link.alert.event.timestamp if link.alert.event else link.alert.created_at,
                    "source_event_id": link.alert.event_id,
                    "source_alert_id": link.alert.id,
                    "confidence": entity.get("confidence", 0.8),
                    "risk_contribution": float(link.risk_contribution or 0),
                }
        return list(derived.values())[:250]

    def _ioc_reference(self, ioc: IOC) -> dict[str, Any]:
        return {
            "id": ioc.id,
            "type": self._value(ioc.type),
            "value": ioc.value,
            "severity": self._value(ioc.severity),
            "confidence": ioc.confidence_score,
            "enrichment_count": len(ioc.enrichments or []),
            "malicious_reports": sum(int(item.malicious_count or 0) for item in ioc.enrichments or []),
        }

    def _evidence_reference(self, evidence: IncidentEvidence) -> dict[str, Any]:
        return {
            "id": evidence.id,
            "type": self._value(evidence.type),
            "value": evidence.value,
            "description": evidence.description,
            "source_event_id": evidence.source_event_id,
            "source_alert_id": evidence.source_alert_id,
            "source_entity_id": evidence.source_entity_id,
            "confidence": evidence.confidence,
            "risk_contribution": evidence.risk_contribution,
            "created_at": evidence.created_at,
        }

    def _timeline(
        self,
        incident: Incident,
        links: Sequence[IncidentAlert],
        events: Iterable[SecurityEvent],
        comments: Sequence[IncidentComment],
        notes: Sequence[InvestigationNote],
    ) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for event in events:
            rows.append({"timestamp": event.timestamp or event.created_at, "type": "event", "title": f"{self._value(event.event_type)} event observed", "resource_id": event.id})
        for link in links:
            rows.append({"timestamp": link.alert.created_at, "type": "alert", "title": f"Alert created: {link.alert.detection_rule.name if link.alert.detection_rule else link.alert.id}", "resource_id": link.alert.id})
        rows.append({"timestamp": incident.created_at, "type": "incident", "title": "Incident created", "resource_id": incident.id})
        rows.extend({"timestamp": item.created_at, "type": "comment", "title": "Analyst comment added", "resource_id": item.id} for item in comments)
        rows.extend({"timestamp": item.created_at, "type": "note", "title": "Investigation note added", "resource_id": item.id} for item in notes)
        return sorted(rows, key=lambda item: ensure_utc(item["timestamp"]))[:200]

    def _mitre(self, incident: Incident, links: Sequence[IncidentAlert]) -> list[dict[str, Any]]:
        if incident.mitre_mappings:
            return [
                {
                    "tactic": row.tactic, "technique_id": row.technique_id,
                    "technique_name": row.technique_name, "sub_technique_id": row.sub_technique_id,
                    "sub_technique_name": row.sub_technique_name, "confidence": row.confidence,
                    "confidence_reasons": row.confidence_reasons or [],
                    "supporting_evidence": row.supporting_evidence or [],
                    "related_source_alert_ids": row.source_alert_ids or [], "attack_stage_order": row.stage_order,
                    "first_seen_at": row.first_seen_at, "last_seen_at": row.last_seen_at,
                }
                for row in sorted(incident.mitre_mappings, key=lambda item: (item.stage_order, item.technique_id))
            ]
        techniques: dict[str, dict[str, Any]] = {}
        for link in links:
            rule = link.alert.detection_rule
            technique_id = rule.mitre_technique_id if rule else None
            if technique_id:
                techniques[technique_id] = {
                    "technique_id": technique_id,
                    "technique_name": self._mitre_name(technique_id),
                    "confidence": min(1.0, max(0.0, float(link.correlation_score or 0) / 100.0)),
                    "reasoning": link.alert.why_matched or "Mapped by the detection rule.",
                    "rule_id": rule.id,
                    "alert_id": link.alert.id,
                }
        stored = incident.attack_technique or {}
        if isinstance(stored, dict) and stored.get("technique_id"):
            techniques.setdefault(str(stored["technique_id"]), stored)
        return list(techniques.values())

    def _evidence_references(
        self,
        incident: Incident,
        *,
        alerts: Sequence[dict[str, Any]],
        events: Sequence[dict[str, Any]],
        detection_matches: Sequence[dict[str, Any]],
        entities: Sequence[dict[str, Any]],
        iocs: Sequence[dict[str, Any]],
        evidence: Sequence[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        refs: list[dict[str, Any]] = [
            {"type": "incident", "id": incident.id, "label": incident.title, "timestamp": utc_isoformat(incident.created_at)}
        ]
        refs.extend(
            {
                "type": "alert",
                "id": item["id"],
                "label": item.get("detection_rule_name") or item["id"],
                "timestamp": utc_isoformat(item.get("created_at")) if item.get("created_at") else None,
            }
            for item in alerts
            if item.get("id")
        )
        refs.extend(
            {
                "type": "event",
                "id": item["id"],
                "label": f"{item.get('event_type') or 'security'} event",
                "timestamp": utc_isoformat(item.get("timestamp") or item.get("created_at")),
            }
            for item in events
            if item.get("id")
        )
        refs.extend(
            {
                "type": "detection_rule",
                "id": item["rule_id"],
                "label": item.get("rule_name") or item["rule_id"],
                "timestamp": None,
            }
            for item in detection_matches
            if item.get("rule_id")
        )
        refs.extend(
            {
                "type": "entity",
                "id": item["id"],
                "label": item.get("value") or item["id"],
                "timestamp": utc_isoformat(item.get("first_seen_at")) if item.get("first_seen_at") else None,
            }
            for item in entities
            if item.get("id") and not str(item["id"]).startswith("derived-")
        )
        refs.extend(
            {"type": "ioc", "id": item["id"], "label": item.get("value") or item["id"], "timestamp": None}
            for item in iocs
            if item.get("id")
        )
        refs.extend(
            {
                "type": "evidence",
                "id": item["id"],
                "label": item.get("description") or item.get("value") or item["id"],
                "timestamp": utc_isoformat(item.get("created_at")) if item.get("created_at") else None,
            }
            for item in evidence
            if item.get("id")
        )
        unique: dict[tuple[str, str], dict[str, Any]] = {}
        for ref in refs:
            unique[(ref["type"], ref["id"])] = ref
        return list(unique.values())[:250]

    def validate_evidence_references(
        self,
        db: Session,
        tenant_id: str,
        incident_id: str,
        references: Sequence[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Return canonical, tenant-scoped navigation metadata for evidence references."""
        allowed_types = {"incident", "alert", "event", "detection_rule", "ioc", "entity", "evidence"}
        ids_by_type: dict[str, set[str]] = defaultdict(set)
        for reference in references[:250]:
            resource_type = str(reference.get("type") or "")
            resource_id = str(reference.get("id") or "")
            if resource_type in allowed_types and resource_id:
                ids_by_type[resource_type].add(resource_id)

        incident = db.query(Incident).filter(
            Incident.id == incident_id,
            Incident.tenant_id == tenant_id,
        ).first()
        maps: dict[str, dict[str, Any]] = {resource_type: {} for resource_type in allowed_types}
        if incident:
            maps["incident"][incident.id] = incident

        alert_ids = ids_by_type["alert"]
        if alert_ids:
            alerts = (
                db.query(Alert)
                .options(joinedload(Alert.detection_rule))
                .join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
                .filter(
                    IncidentAlert.incident_id == incident_id,
                    Alert.tenant_id == tenant_id,
                    Alert.id.in_(alert_ids),
                )
                .all()
            )
            maps["alert"] = {item.id: item for item in alerts}

        event_ids = ids_by_type["event"]
        if event_ids:
            related_event_ids = (
                db.query(Alert.event_id)
                .join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
                .filter(
                    IncidentAlert.incident_id == incident_id,
                    Alert.tenant_id == tenant_id,
                    Alert.event_id.isnot(None),
                )
            )
            events = (
                db.query(SecurityEvent)
                .filter(
                    SecurityEvent.tenant_id == tenant_id,
                    SecurityEvent.id.in_(event_ids),
                    SecurityEvent.id.in_(related_event_ids),
                )
                .all()
            )
            maps["event"] = {item.id: item for item in events}

        rule_ids = ids_by_type["detection_rule"]
        if rule_ids:
            related_rule_ids = (
                db.query(Alert.detection_rule_id)
                .join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
                .filter(
                    IncidentAlert.incident_id == incident_id,
                    Alert.tenant_id == tenant_id,
                    Alert.detection_rule_id.isnot(None),
                )
            )
            rules = (
                db.query(DetectionRule)
                .filter(
                    DetectionRule.tenant_id == tenant_id,
                    DetectionRule.id.in_(rule_ids),
                    DetectionRule.id.in_(related_rule_ids),
                )
                .all()
            )
            maps["detection_rule"] = {item.id: item for item in rules}

        ioc_ids = ids_by_type["ioc"]
        if ioc_ids:
            iocs = (
                db.query(IOC)
                .join(IncidentIOC, IncidentIOC.ioc_id == IOC.id)
                .filter(
                    IncidentIOC.incident_id == incident_id,
                    IncidentIOC.tenant_id == tenant_id,
                    IOC.tenant_id == tenant_id,
                    IOC.id.in_(ioc_ids),
                )
                .all()
            )
            maps["ioc"] = {item.id: item for item in iocs}

        entity_ids = ids_by_type["entity"]
        if entity_ids:
            entities = db.query(IncidentEntity).filter(
                IncidentEntity.incident_id == incident_id,
                IncidentEntity.tenant_id == tenant_id,
                IncidentEntity.id.in_(entity_ids),
            ).all()
            maps["entity"] = {item.id: item for item in entities}

        evidence_ids = ids_by_type["evidence"]
        if evidence_ids:
            evidence_rows = db.query(IncidentEvidence).filter(
                IncidentEvidence.incident_id == incident_id,
                IncidentEvidence.tenant_id == tenant_id,
                IncidentEvidence.id.in_(evidence_ids),
            ).all()
            maps["evidence"] = {item.id: item for item in evidence_rows}

        validated: list[dict[str, Any]] = []
        for reference in references[:250]:
            resource_type = str(reference.get("type") or "")
            resource_id = str(reference.get("id") or "")
            if resource_type not in allowed_types:
                validated.append({
                    "type": resource_type or "unsupported",
                    "id": resource_id,
                    "label": "Unsupported evidence reference",
                    "timestamp": None,
                    "navigation_path": None,
                    "available": False,
                    "unavailable_reason": "This evidence type is not supported for navigation.",
                })
                continue
            resource = maps[resource_type].get(resource_id)
            if resource is None:
                validated.append({
                    "type": resource_type,
                    "id": resource_id,
                    "label": "Evidence unavailable",
                    "timestamp": None,
                    "navigation_path": None,
                    "available": False,
                    "unavailable_reason": "The referenced object was deleted, is unrelated, or is outside the current tenant.",
                })
                continue
            label, timestamp, path = self._canonical_evidence_navigation(resource_type, resource, incident_id)
            validated.append({
                "type": resource_type,
                "id": resource_id,
                "label": label,
                "timestamp": utc_isoformat(timestamp) if timestamp else None,
                "navigation_path": path,
                "available": True,
                "unavailable_reason": None,
            })
        return validated

    def _canonical_evidence_navigation(
        self,
        resource_type: str,
        resource: Any,
        incident_id: str,
    ) -> tuple[str, datetime | None, str | None]:
        if resource_type == "incident":
            return resource.title, resource.created_at, f"/incidents/{resource.id}"
        if resource_type == "alert":
            label = resource.detection_rule.name if resource.detection_rule else f"Alert {resource.id}"
            return label, resource.created_at, f"/alerts/{resource.id}"
        if resource_type == "event":
            return f"{self._value(resource.event_type)} event", resource.timestamp or resource.created_at, f"/events/{resource.id}"
        if resource_type == "detection_rule":
            return resource.name, resource.created_at, f"/detection-rules/{resource.id}"
        if resource_type == "ioc":
            return resource.value, resource.created_at, f"/threat-intel/{resource.id}"
        if resource_type == "entity":
            path = f"/events/{resource.source_event_id}" if resource.source_event_id else (
                f"/alerts/{resource.source_alert_id}" if resource.source_alert_id else f"/incidents/{incident_id}"
            )
            return resource.value, resource.first_seen_at or resource.created_at, path
        return resource.description or resource.value, resource.created_at, f"/incidents/{incident_id}"

    def _recommended_questions(self, entities: Sequence[dict[str, Any]], iocs: Sequence[dict[str, Any]], mitre: Sequence[dict[str, Any]]) -> list[str]:
        questions = [
            "Which alert triggered this incident and what exact condition matched?",
            "What happened immediately before and after the primary event?",
            "Which evidence supports the current severity and risk score?",
            "What containment action requires analyst approval?",
        ]
        if entities:
            questions.append("Which affected user, host, or process should be investigated first?")
        if iocs:
            questions.append("Which IOCs are confirmed malicious and where else were they observed?")
        if mitre:
            questions.append("What additional telemetry would confirm the mapped MITRE ATT&CK techniques?")
        return questions

    def _limitations(self, links: Sequence[IncidentAlert], events: dict[str, SecurityEvent], entities: Sequence[Any]) -> list[str]:
        limitations: list[str] = []
        if not links:
            limitations.append("No source alerts are linked to this incident.")
        if not events:
            limitations.append("No source events are linked through the incident alerts.")
        if not entities:
            limitations.append("No structured entities have been extracted for this incident.")
        return limitations

    def _creation_reason(self, alert: Alert, correlation_reason: str) -> str:
        rule_name = alert.detection_rule.name if alert.detection_rule else "configured detection logic"
        match = alert.why_matched or alert.matched_condition or "the rule condition matched"
        return f"Alert {alert.id} triggered by {rule_name} created the incident because {match}. {correlation_reason}".strip()

    def _legacy_creation_reason(self, primary_link: IncidentAlert | None) -> str:
        if primary_link is None:
            return "The available data does not identify a source alert for this incident."
        return self._creation_reason(primary_link.alert, primary_link.correlation_reason or "")

    def _attack_summary(self, primary: Alert, alerts: Sequence[Alert]) -> str:
        rule = primary.detection_rule.name if primary.detection_rule else "Detection logic"
        return f"{rule} identified suspicious activity in {len(alerts)} related alert(s). {primary.why_matched or ''}".strip()

    def _correlation_key(self, alerts: Sequence[Alert]) -> str | None:
        entity_sets = [
            {(entity["type"], entity["normalized_value"]) for entity in self.extract_alert_entities(alert)}
            for alert in alerts
        ]
        if not entity_sets:
            return None
        shared = set.intersection(*entity_sets) if len(entity_sets) > 1 else entity_sets[0]
        if not shared:
            return None
        entity_type, value = sorted(shared)[0]
        return f"{entity_type}:{value}"[:255]

    def _observed_at(self, alert: Alert) -> datetime:
        value = alert.event.timestamp if alert.event and alert.event.timestamp else alert.created_at
        return ensure_utc(value or datetime.now(timezone.utc))

    def _alert_weight(self, alert: Alert) -> float:
        return self._SEVERITY_WEIGHT.get(alert.severity, 20.0)

    def _walk(self, value: Any, prefix: str = "") -> Iterable[tuple[str, Any]]:
        if isinstance(value, dict):
            for key, nested in value.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                yield path, nested
                yield from self._walk(nested, path)
        elif isinstance(value, list):
            for nested in value[:100]:
                yield from self._walk(nested, prefix)

    def _scalars(self, value: Any) -> list[Any]:
        if isinstance(value, list):
            return [item for item in value[:100] if not isinstance(item, (dict, list))]
        if isinstance(value, dict):
            for preferred in ("name", "value", "ip", "hostname", "path", "email"):
                if self._usable(value.get(preferred)):
                    return [value[preferred]]
            return []
        return [value]

    def _usable(self, value: Any) -> bool:
        return value is not None and value != "" and not isinstance(value, bool)

    def _normalize(self, entity_type: str, value: Any) -> str:
        text = str(value).strip()
        if not text or len(text) > 2048:
            return ""
        if entity_type in {"process", "file", "host", "domain", "email_address", "file_hash", "log_source"}:
            text = text.lower()
        if entity_type == "ip_address":
            try:
                return ipaddress.ip_address(text).compressed.lower()
            except ValueError:
                return ""
        if entity_type == "url":
            parsed = urlsplit(text)
            return text if parsed.scheme.lower() in {"http", "https"} and parsed.hostname else ""
        if entity_type == "email_address":
            return text if re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", text) else ""
        if entity_type == "domain":
            domain = text.rstrip(".")
            pattern = r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
            return domain if re.fullmatch(pattern, domain) else ""
        if entity_type == "file_hash":
            candidate = text.removeprefix("sha256:").removeprefix("sha1:").removeprefix("md5:")
            return candidate if len(candidate) in {32, 40, 64} and re.fullmatch(r"[0-9a-f]+", candidate) else ""
        return text

    def _role_from_path(self, path: str) -> str:
        lowered = path.lower()
        if "source" in lowered or "src" in lowered:
            return "source"
        if "destination" in lowered or "dst" in lowered or "target" in lowered:
            return "target"
        if "parent" in lowered:
            return "parent_process"
        return "observed"

    def _value(self, value: Any) -> Any:
        return value.value if hasattr(value, "value") else value

    def _mitre_name(self, technique_id: str) -> str:
        names = {
            "T1059": "Command and Scripting Interpreter",
            "T1059.001": "PowerShell",
            "T1110": "Brute Force",
            "T1071": "Application Layer Protocol",
            "T1047": "Windows Management Instrumentation",
        }
        return names.get(technique_id, "Mapped MITRE ATT&CK technique")


incident_intelligence_service = IncidentIntelligenceService()
