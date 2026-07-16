from __future__ import annotations

import json
from typing import Any, Sequence

from src.models.sqlalchemy import Alert, Incident
from src.services.llm_provider import llm_provider
from src.services.mitre_service import mitre_service


class AIService:
    def analyze_incident(
        self,
        incident: Incident,
        alerts: Sequence[Alert],
        correlation_reasons: Sequence[str],
        threat_intel_results: Sequence[dict[str, Any]],
    ) -> dict[str, Any]:
        attack_technique = mitre_service.map_incident(incident.title, alerts)
        prompt = self._build_prompt(
            incident=incident,
            alerts=alerts,
            correlation_reasons=correlation_reasons,
            threat_intel_results=threat_intel_results,
            attack_technique=attack_technique,
        )

        analysis = llm_provider.generate_structured_analysis(prompt)
        if not analysis:
            analysis = self._fallback_analysis(
                incident=incident,
                alerts=alerts,
                correlation_reasons=correlation_reasons,
                threat_intel_results=threat_intel_results,
                attack_technique=attack_technique,
            )

        return {
            "summary": str(analysis.get("summary") or self._fallback_analysis(
                incident, alerts, correlation_reasons, threat_intel_results, attack_technique
            )["summary"]),
            "why_suspicious": str(analysis.get("why_suspicious") or self._build_why_suspicious(correlation_reasons, threat_intel_results)),
            "attack_technique": analysis.get("attack_technique") or attack_technique,
            "recommended_actions": list(analysis.get("recommended_actions") or self._recommended_actions(incident, attack_technique, threat_intel_results)),
            "threat_intel_results": list(threat_intel_results),
        }

    def _build_prompt(
        self,
        incident: Incident,
        alerts: Sequence[Alert],
        correlation_reasons: Sequence[str],
        threat_intel_results: Sequence[dict[str, Any]],
        attack_technique: dict[str, Any],
    ) -> str:
        alert_context = [
            {
                "severity": alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity),
                "activity": (alert.ocsf_data or {}).get("activity_name"),
                "class_name": (alert.ocsf_data or {}).get("class_name"),
                "raw_data": alert.raw_data,
            }
            for alert in alerts
        ]
        return json.dumps({
            "incident": {
                "title": incident.title,
                "description": incident.description,
                "risk_score": incident.risk_score,
                "severity": incident.severity.value if hasattr(incident.severity, "value") else str(incident.severity),
            },
            "correlation_reasons": list(correlation_reasons),
            "mitre_mapping_candidate": attack_technique,
            "threat_intelligence": list(threat_intel_results),
            "related_alerts": alert_context,
        }, default=str)

    def _fallback_analysis(
        self,
        incident: Incident,
        alerts: Sequence[Alert],
        correlation_reasons: Sequence[str],
        threat_intel_results: Sequence[dict[str, Any]],
        attack_technique: dict[str, Any],
    ) -> dict[str, Any]:
        summary = (
            f"{incident.title} contains {len(alerts)} related alert(s) with a current risk score of "
            f"{float(incident.risk_score or 0):.0f}. Analysts should review authentication, endpoint, and network evidence together."
        )
        why_suspicious = self._build_why_suspicious(correlation_reasons, threat_intel_results)
        return {
            "summary": summary,
            "why_suspicious": why_suspicious,
            "attack_technique": attack_technique,
            "recommended_actions": self._recommended_actions(incident, attack_technique, threat_intel_results),
        }

    def _build_why_suspicious(
        self,
        correlation_reasons: Sequence[str],
        threat_intel_results: Sequence[dict[str, Any]],
    ) -> str:
        parts = list(correlation_reasons[:2])
        malicious_hits = [
            finding["indicator"]
            for finding in threat_intel_results
            if int(finding.get("risk_impact", 0)) > 0
        ]
        if malicious_hits:
            parts.append(f"Threat intelligence flagged {', '.join(malicious_hits)} as suspicious or malicious")
        return "; ".join(parts) if parts else "The incident combines multiple suspicious signals that warrant investigation."

    def _recommended_actions(
        self,
        incident: Incident,
        attack_technique: dict[str, Any],
        threat_intel_results: Sequence[dict[str, Any]],
    ) -> list[str]:
        actions = [
            "Review all related alerts and confirm the full event timeline.",
            "Validate impacted accounts, hosts, or endpoints for unauthorized activity.",
            "Preserve logs and evidence relevant to the incident for analyst review.",
        ]
        if attack_technique.get("technique_id") == "T1110":
            actions.extend(
                [
                    "Reset or challenge the affected account credentials and review MFA events.",
                    "Investigate the originating IP address for repeated authentication attempts.",
                ]
            )
        if attack_technique.get("technique_id") == "T1204":
            actions.extend(
                [
                    "Isolate the affected host and quarantine the suspicious file or hash.",
                    "Review endpoint telemetry for process execution and persistence artifacts.",
                ]
            )
        if any(int(item.get("risk_impact", 0)) > 0 for item in threat_intel_results):
            actions.append("Block or monitor the malicious indicators identified by threat intelligence.")
        return list(dict.fromkeys(actions))[:5]


ai_service = AIService()
