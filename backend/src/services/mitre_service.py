from __future__ import annotations

from typing import Sequence

from src.models.sqlalchemy import Alert


class MitreService:
    MAPPINGS = {
        "T1110": {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "description": "Adversaries may use repeated attempts to guess valid account credentials.",
        },
        "T1059.001": {
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "description": "Adversaries may abuse PowerShell for execution and post-exploitation activity.",
        },
        "T1204": {
            "technique_id": "T1204",
            "technique_name": "User Execution",
            "description": "Adversaries may rely on user execution of malicious files or payloads.",
        },
        "T1071": {
            "technique_id": "T1071",
            "technique_name": "Application Layer Protocol",
            "description": "Adversaries may use application layer protocols to communicate with compromised systems.",
        },
        "T1136": {
            "technique_id": "T1136",
            "technique_name": "Create Account",
            "description": "Adversaries may create accounts to maintain access to compromised systems.",
        },
        "UNKNOWN": {
            "technique_id": "UNKNOWN",
            "technique_name": "Unmapped Technique",
            "description": "No direct MITRE ATT&CK mapping was identified from the current incident context.",
        },
    }

    def map_incident(self, incident_title: str, alerts: Sequence[Alert]) -> dict:
        # First check if any alert has a detection rule with mitre_technique_id
        for alert in alerts:
            if hasattr(alert, 'detection_rule') and alert.detection_rule:
                if alert.detection_rule.mitre_technique_id:
                    if alert.detection_rule.mitre_technique_id in self.MAPPINGS:
                        return self.MAPPINGS[alert.detection_rule.mitre_technique_id]
                    else:
                        return {
                            "technique_id": alert.detection_rule.mitre_technique_id,
                            "technique_name": alert.detection_rule.mitre_technique_id,
                            "description": "MITRE technique from detection rule."
                        }
        
        title = incident_title.lower()
        raw_text = " ".join(str(alert.raw_data).lower() for alert in alerts)
        class_names = {
            str((alert.ocsf_data or {}).get("class_name", "")).lower() for alert in alerts if alert.ocsf_data
        }

        if "powershell" in raw_text:
            return self.MAPPINGS["T1059.001"]
        if "malware" in title or "malware" in class_names:
            return self.MAPPINGS["T1204"]
        if "account takeover" in title or "authentication" in class_names or "brute_force" in raw_text:
            return self.MAPPINGS["T1110"]
        if "network" in class_names:
            return self.MAPPINGS["T1071"]
        if "user_creation" in raw_text or "identity" in class_names:
            return self.MAPPINGS["T1136"]
        return self.MAPPINGS["UNKNOWN"]


mitre_service = MitreService()
