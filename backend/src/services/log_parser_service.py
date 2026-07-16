from typing import Dict, Any, Optional
from src.models.sqlalchemy import EventType, Severity


class BaseLogParser:
    def parse(self, raw_log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        raise NotImplementedError("Implement parse method")


class WindowsEventParser(BaseLogParser):
    def parse(self, raw_log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        event_id = raw_log.get("EventID")
        if not event_id:
            return None
        
        normalized = {
            "event_type": EventType.PROCESS,
            "severity": Severity.LOW,
            "source": "windows_edr"
        }
        
        if event_id == 4688:
            normalized["event_type"] = EventType.PROCESS
            image = raw_log.get("Image", "")
            normalized["process"] = image
            if "powershell.exe" in image.lower() or "cmd.exe" in image.lower() or "wscript.exe" in image.lower():
                normalized["severity"] = Severity.HIGH
        elif event_id in (4624, 4625):
            normalized["event_type"] = EventType.LOGIN
            if event_id == 4625:
                normalized["severity"] = Severity.HIGH
        return normalized


class LinuxAuditParser(BaseLogParser):
    def parse(self, raw_log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        message = str(raw_log.get("message", "")).lower()
        normalized = {
            "event_type": EventType.PROCESS,
            "severity": Severity.LOW,
            "source": "linux_audit"
        }
        if "failed password" in message:
            normalized["event_type"] = EventType.LOGIN
            normalized["severity"] = Severity.HIGH
        return normalized


class LogParserService:
    def __init__(self):
        self.parsers = {
            "windows_edr": WindowsEventParser(),
            "linux_audit": LinuxAuditParser()
        }
    
    def parse_log(self, source_type: str, raw_log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        parser = self.parsers.get(source_type)
        if not parser:
            return None
        return parser.parse(raw_log)


log_parser_service = LogParserService()
