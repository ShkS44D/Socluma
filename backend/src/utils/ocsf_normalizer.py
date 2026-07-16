from typing import Dict, Any
from datetime import datetime, timezone
from src.models.sqlalchemy import Severity
from src.utils.datetime_utils import ensure_utc, get_utc_now


class OCSFNormalizer:
    def __init__(self):
        self.normalizers = {
            "authentication": self._normalize_authentication,
            "network": self._normalize_network,
            "malware": self._normalize_malware,
            "process": self._normalize_process,
            "identity": self._normalize_identity,
            "default": self._normalize_default
        }
    
    def normalize(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        # Determine the event type
        event_type = raw_data.get("event_type", raw_data.get("event", "default")).lower()
        
        # Map vendor event types to OCSF classes
        class_mapping = {
            "login": "authentication",
            "login_failed": "authentication",
            "failed_login": "authentication",
            "brute_force": "authentication",
            "network": "network",
            "connection": "network",
            "suspicious_network": "network",
            "outbound_connection": "network",
            "malware": "malware",
            "malware_detection": "malware",
            "virus": "malware",
            "process": "process",
            "process_created": "process",
            "powershell": "process",
            "powershell_execution": "process",
            "user_created": "identity",
            "new_user": "identity",
            "user_creation": "identity",
        }
        
        normalizer_key = class_mapping.get(event_type, "default")
        return self.normalizers[normalizer_key](raw_data)
    
    def _normalize_authentication(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        activity_map = {
            "login": "Login Success",
            "login_failed": "Login Failure",
            "failed_login": "Login Failure",
            "brute_force": "Brute Force Attempt"
        }
        
        return {
            "class_name": "Authentication",
            "activity_name": activity_map.get(
                raw_data.get("event_type", raw_data.get("event")), "Login Attempt"
            ),
            "time": raw_data.get("timestamp", get_utc_now().isoformat()),
            "user": {
                "name": raw_data.get("user"),
                "type": "person"
            },
            "source": {
                "ip": raw_data.get("ip"),
                "port": raw_data.get("port")
            },
            "severity": self._convert_severity(raw_data.get("severity")),
            "message": raw_data.get("message", "Authentication event"),
            "raw_data": raw_data
        }
    
    def _normalize_network(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "class_name": "Network",
            "activity_name": raw_data.get("event_type", raw_data.get("event", "Network Activity")),
            "time": raw_data.get("timestamp", get_utc_now().isoformat()),
            "source": {
                "ip": raw_data.get("source_ip", raw_data.get("ip")),
                "port": raw_data.get("source_port")
            },
            "destination": {
                "ip": raw_data.get("destination_ip", raw_data.get("dst_ip")),
                "port": raw_data.get("destination_port", raw_data.get("dst_port"))
            },
            "protocol": raw_data.get("protocol"),
            "severity": self._convert_severity(raw_data.get("severity")),
            "message": raw_data.get("message", "Network event"),
            "raw_data": raw_data
        }
    
    def _normalize_malware(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "class_name": "Malware",
            "activity_name": raw_data.get("event_type", raw_data.get("event", "Malware Detected")),
            "time": raw_data.get("timestamp", get_utc_now().isoformat()),
            "malware": {
                "name": raw_data.get("malware_name", raw_data.get("virus_name")),
                "type": raw_data.get("malware_type"),
                "hash": raw_data.get("file_hash", raw_data.get("hash"))
            },
            "file": {
                "name": raw_data.get("file_name"),
                "path": raw_data.get("file_path")
            },
            "severity": self._convert_severity(raw_data.get("severity"), Severity.HIGH),
            "message": raw_data.get("message", "Malware detected"),
            "raw_data": raw_data
        }
    
    def _normalize_process(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        activity_map = {
            "process": "Process Created",
            "process_created": "Process Created",
            "powershell": "PowerShell Execution",
            "powershell_execution": "PowerShell Execution"
        }
        
        return {
            "class_name": "Process",
            "activity_name": activity_map.get(
                raw_data.get("event_type", raw_data.get("event")), "Process Activity"
            ),
            "time": raw_data.get("timestamp", get_utc_now().isoformat()),
            "process": {
                "name": raw_data.get("process_name", raw_data.get("process")),
                "pid": raw_data.get("pid"),
                "command_line": raw_data.get("command_line")
            },
            "file": {
                "name": raw_data.get("file_name"),
                "path": raw_data.get("file_path")
            },
            "severity": self._convert_severity(raw_data.get("severity")),
            "message": raw_data.get("message", "Process event"),
            "raw_data": raw_data
        }
    
    def _normalize_identity(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        activity_map = {
            "user_created": "User Created",
            "new_user": "User Created",
            "user_creation": "User Created"
        }
        
        return {
            "class_name": "Identity",
            "activity_name": activity_map.get(
                raw_data.get("event_type", raw_data.get("event")), "Identity Activity"
            ),
            "time": raw_data.get("timestamp", get_utc_now().isoformat()),
            "user": {
                "name": raw_data.get("user"),
                "type": "person"
            },
            "severity": self._convert_severity(raw_data.get("severity")),
            "message": raw_data.get("message", "Identity event"),
            "raw_data": raw_data
        }
    
    def _normalize_default(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "class_name": "Generic",
            "activity_name": raw_data.get("event_type", raw_data.get("event", "Unknown")),
            "time": raw_data.get("timestamp", get_utc_now().isoformat()),
            "severity": self._convert_severity(raw_data.get("severity")),
            "message": raw_data.get("message", "Unknown event type"),
            "raw_data": raw_data
        }
    
    def _convert_severity(self, severity: str, default: Severity = Severity.MEDIUM) -> Severity:
        severity_map = {
            "low": Severity.LOW,
            "medium": Severity.MEDIUM,
            "high": Severity.HIGH,
            "critical": Severity.CRITICAL,
            "info": Severity.LOW,
            "warning": Severity.MEDIUM,
            "error": Severity.HIGH,
            "fatal": Severity.CRITICAL
        }
        return severity_map.get(str(severity).lower(), default)


# Singleton instance
_normalizer = OCSFNormalizer()


def normalize_alert(raw_data: Dict[str, Any]) -> Dict[str, Any]:
    return _normalizer.normalize(raw_data)
