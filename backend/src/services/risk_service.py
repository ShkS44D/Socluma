from __future__ import annotations

from typing import Any, Iterable, Sequence

from sqlalchemy import func
from sqlalchemy.orm import Session

from src.models.sqlalchemy import (
    Alert, Feedback, Incident, Severity, Classification, 
    Asset, AssetCriticality, MitreTechnique, MitreTechniqueImpact
)


class RiskService:
    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 40,
        Severity.HIGH: 30,
        Severity.MEDIUM: 20,
        Severity.LOW: 10,
    }

    ASSET_CRITICALITY_WEIGHTS = {
        AssetCriticality.CRITICAL: 30,
        AssetCriticality.HIGH: 20,
        AssetCriticality.MEDIUM: 10,
        AssetCriticality.LOW: 0,
    }

    def calculate_risk(
        self,
        db: Session,
        tenant_id: str,
        alerts: Sequence[Alert],
        correlation_reasons: Iterable[str],
        incident_title: str,
        threat_intel_results: Sequence[dict] | None = None,
    ) -> dict:
        alerts = list(alerts)
        reasons = list(dict.fromkeys(reason for reason in correlation_reasons if reason))
        threat_intel_results = list(threat_intel_results or [])

        base_score = max(
            (self.SEVERITY_WEIGHTS.get(alert.severity, 20) for alert in alerts),
            default=0,
        )
        multi_alert_bonus = min(max(len(alerts) - 1, 0) * 10, 25)
        suspicious_behavior_bonus = self._suspicious_behavior_bonus(alerts, reasons)
        threat_intel_bonus = self._threat_intel_bonus(threat_intel_results)
        asset_criticality_bonus = self._asset_criticality_bonus(db, tenant_id, alerts)
        mitre_technique_bonus = self._mitre_technique_bonus(db, alerts)
        false_positive_penalty = self._false_positive_penalty(db, tenant_id, incident_title)
        true_positive_bonus = self._true_positive_bonus(db, tenant_id, incident_title)

        uncapped_score = (
            base_score
            + multi_alert_bonus
            + suspicious_behavior_bonus
            + threat_intel_bonus
            + asset_criticality_bonus
            + mitre_technique_bonus
            + true_positive_bonus
            - false_positive_penalty
        )
        score = max(0, min(100, uncapped_score))
        bounding_adjustment = score - uncapped_score

        severity = self._score_to_severity(score)
        reason = self._reason_text(alerts, reasons, score, threat_intel_results)

        return {
            "risk_score": float(score),
            "severity": severity,
            "reason": reason,
            "breakdown": {
                "base_severity": base_score,
                "multiple_alerts": multi_alert_bonus,
                "suspicious_behavior": suspicious_behavior_bonus,
                "threat_intelligence": threat_intel_bonus,
                "asset_criticality": asset_criticality_bonus,
                "mitre_techniques": mitre_technique_bonus,
                "confirmed_true_positive": true_positive_bonus,
                "false_positive_history_penalty": -false_positive_penalty,
                "bounding_adjustment": bounding_adjustment,
                "uncapped_total": float(uncapped_score),
                "total": float(score),
                "reason": reason,
            },
        }

    def _asset_criticality_bonus(self, db: Session, tenant_id: str, alerts: Sequence[Alert]) -> int:
        max_bonus = 0
        indicators = {
            value
            for alert in alerts
            for value in (
                self._indicators(alert).get("ip"),
                self._indicators(alert).get("hostname"),
            )
            if value
        }
        if not indicators:
            return 0
        assets = (
            db.query(Asset)
            .filter(
                Asset.tenant_id == tenant_id,
                (Asset.ip_address.in_(indicators)) | (Asset.hostname.in_(indicators)),
            )
            .all()
        )
        asset_map = {}
        for asset in assets:
            if asset.ip_address:
                asset_map[asset.ip_address] = asset.criticality
            if asset.hostname:
                asset_map[asset.hostname] = asset.criticality

        for alert in alerts:
            indicators = self._indicators(alert)
            for key in ["ip", "hostname"]:
                value = indicators.get(key)
                if value and value in asset_map:
                    weight = self.ASSET_CRITICALITY_WEIGHTS.get(asset_map[value], 0)
                    if weight > max_bonus:
                        max_bonus = weight

        return min(max_bonus, 30)

    def _mitre_technique_bonus(self, db: Session, alerts: Sequence[Alert]) -> int:
        max_bonus = 0
        alert_techniques = {
            technique_id
            for alert in alerts
            for technique_id in self._extract_mitre_techniques(alert)
        }
        if not alert_techniques:
            return 0
        technique_impacts = {
            item.technique_id: item.impact_score
            for item in db.query(MitreTechniqueImpact)
            .filter(MitreTechniqueImpact.technique_id.in_(alert_techniques))
            .all()
        }
        
        for technique_id in alert_techniques:
            score = technique_impacts.get(technique_id)
            if score and score > max_bonus:
                max_bonus = score
        
        return min(max_bonus, 25)

    def _extract_mitre_techniques(self, alert: Alert) -> list[str]:
        ocsf = alert.ocsf_data or {}
        attack_techniques = ocsf.get("attack_techniques", [])
        if not attack_techniques and alert.incident:
            attack_techniques = alert.incident.attack_technique or []
        
        if isinstance(attack_techniques, dict):
            return [str(k) for k in attack_techniques.keys()]
        elif isinstance(attack_techniques, list):
            return [str(t) for t in attack_techniques]
        return []

    def _indicators(self, alert: Alert) -> dict:
        raw = alert.raw_data or {}
        ocsf = alert.ocsf_data or {}
        user = ocsf.get("user")
        source = ocsf.get("source")
        destination = ocsf.get("destination")
        device = ocsf.get("device")
        return {
            "user": raw.get("user") or self._field_value(user, "name"),
            "ip": raw.get("ip")
            or raw.get("source_ip")
            or self._field_value(source, "ip")
            or self._field_value(destination, "ip"),
            "hostname": raw.get("hostname")
            or raw.get("device")
            or raw.get("host")
            or self._field_value(device, "hostname"),
        }

    def _field_value(self, value: Any, key: str) -> Any:
        if isinstance(value, dict):
            return value.get(key)
        if isinstance(value, str):
            return value
        return None

    def _suspicious_behavior_bonus(self, alerts: Sequence[Alert], reasons: Sequence[str]) -> int:
        bonus = 0
        activities = [
            str((alert.ocsf_data or {}).get("activity_name", "")).lower() for alert in alerts
        ]
        event_types = [
            str((alert.raw_data or {}).get("event_type", "")).lower() for alert in alerts
        ]
        class_names = {
            str(alert.ocsf_data.get("class_name", "")).lower() for alert in alerts if alert.ocsf_data
        }

        if "authentication" in class_names:
            auth_reasons = " ".join(reasons).lower()
            has_failed_login = any(
                "failed" in activity
                or "brute force" in activity
                or activity == "login attempt"
                or event_type in {"login_failed", "failed_login", "brute_force"}
                for activity, event_type in zip(activities, event_types)
            )
            has_successful_login = any(
                activity == "login" or event_type == "login"
                for activity, event_type in zip(activities, event_types)
            )
            if has_failed_login and has_successful_login:
                bonus += 20
            elif "same ip" in auth_reasons and "same user" in auth_reasons:
                bonus += 15

        if "malware" in class_names:
            bonus += 20

        if any("hostname" in reason.lower() or "device" in reason.lower() for reason in reasons):
            bonus += 10

        if len(alerts) >= 3:
            bonus += 10

        return min(bonus, 35)

    def _threat_intel_bonus(self, threat_intel_results: Sequence[dict]) -> int:
        total = sum(int(result.get("risk_impact", 0)) for result in threat_intel_results)
        return min(total, 35)

    def _false_positive_penalty(self, db: Session, tenant_id: str, incident_title: str) -> int:
        false_positive_count = (
            db.query(func.count(Feedback.id))
            .join(Incident, Incident.id == Feedback.incident_id)
            .filter(
                Incident.tenant_id == tenant_id, 
                Incident.title == incident_title, 
                Feedback.classification == Classification.FALSE_POSITIVE
            )
            .scalar()
        )
        return min((false_positive_count or 0) * 10, 30)

    def _true_positive_bonus(self, db: Session, tenant_id: str, incident_title: str) -> int:
        true_positive_count = (
            db.query(func.count(Feedback.id))
            .join(Incident, Incident.id == Feedback.incident_id)
            .filter(
                Incident.tenant_id == tenant_id, 
                Incident.title == incident_title, 
                Feedback.classification == Classification.TRUE_POSITIVE
            )
            .scalar()
        )
        return min((true_positive_count or 0) * 5, 15)

    def _score_to_severity(self, score: float) -> Severity:
        if score >= 80:
            return Severity.CRITICAL
        if score >= 60:
            return Severity.HIGH
        if score >= 35:
            return Severity.MEDIUM
        return Severity.LOW

    def _reason_text(
        self,
        alerts: Sequence[Alert],
        reasons: Sequence[str],
        score: float,
        threat_intel_results: Sequence[dict],
    ) -> str:
        if reasons:
            base_reason = "; ".join(reasons)
            if threat_intel_results:
                enriched = ", ".join(
                    result["indicator"]
                    for result in threat_intel_results
                    if int(result.get("risk_impact", 0)) > 0
                )
                if enriched:
                    return f"{base_reason}; threat intelligence flagged {enriched}"
            return base_reason
        if any((alert.ocsf_data or {}).get("class_name") == "Malware" for alert in alerts):
            return "Malware activity detected and prioritized for analyst review"
        if score >= 60:
            return "Multiple related alerts indicate suspicious activity"
        return "Incident created from correlated alert activity"


risk_service = RiskService()
