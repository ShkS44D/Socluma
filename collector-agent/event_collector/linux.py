import platform
import re
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from utils.logger import setup_logger
from api_client import BackendEventType, BackendSeverity

logger = setup_logger("linux_collector")

class LinuxEventCollector:
    AUTH_LOG_PATH = "/var/log/auth.log"
    SYSLOG_PATH = "/var/log/syslog"
    
    def __init__(self):
        self.is_linux = platform.system().lower() == "linux"
        self.log_file_position = 0
        self._check_log_files()
    
    def _check_log_files(self):
        import os
        if self.is_linux:
            if os.path.exists(self.AUTH_LOG_PATH):
                self.log_file_path = self.AUTH_LOG_PATH
                logger.info(f"Using auth log: {self.AUTH_LOG_PATH}")
            elif os.path.exists(self.SYSLOG_PATH):
                self.log_file_path = self.SYSLOG_PATH
                logger.info(f"Using syslog: {self.SYSLOG_PATH}")
            else:
                logger.warning("No supported log files found; event collection is unavailable")
                self.log_file_path = None
        else:
            logger.warning("Not on Linux; Linux event collection is unavailable")
            self.log_file_path = None
    
    def collect_events(self) -> List[Dict[str, Any]]:
        if not self.is_linux or not self.log_file_path:
            return []
        
        events = []
        try:
            with open(self.log_file_path, 'r', encoding='utf-8', errors='replace') as f:
                f.seek(self.log_file_position)
                new_lines = f.readlines()
                self.log_file_position = f.tell()
            
            for line in new_lines:
                parsed = self._parse_auth_line(line.strip())
                if parsed:
                    events.append(parsed)
                    
        except Exception as e:
            logger.error(f"Error reading Linux log file: {e}")
        
        return events

    def _parse_auth_line(self, line: str) -> Optional[Dict[str, Any]]:
        try:
            event_type = None
            raw_event = {}
            normalized_event = {}
            severity = BackendSeverity.MEDIUM
            
            # Failed SSH login
            if "Failed password" in line:
                event_type = BackendEventType.LOGIN
                severity = BackendSeverity.HIGH
                # Extract user from line like: "Failed password for invalid user testuser from 192.168.1.100"
                match = re.search(r'for (invalid user )?(?P<user>\S+)', line)
                if match:
                    raw_event["user"] = match.group("user")
                    normalized_event["user"] = match.group("user")
                # Extract IP
                ip_match = re.search(r'from (?P<ip>\S+)', line)
                if ip_match:
                    raw_event["source_ip"] = ip_match.group("ip")
                    normalized_event["source_ip"] = ip_match.group("ip")
                raw_event["status"] = "failure"
                normalized_event["status"] = "failure"
                
            # Successful SSH login
            elif "Accepted password" in line or "Accepted publickey" in line:
                event_type = BackendEventType.LOGIN
                # Extract user
                match = re.search(r'for (?P<user>\S+)', line)
                if match:
                    raw_event["user"] = match.group("user")
                    normalized_event["user"] = match.group("user")
                # Extract IP
                ip_match = re.search(r'from (?P<ip>\S+)', line)
                if ip_match:
                    raw_event["source_ip"] = ip_match.group("ip")
                    normalized_event["source_ip"] = ip_match.group("ip")
                raw_event["status"] = "success"
                normalized_event["status"] = "success"
            
            now_dt = datetime.now(timezone.utc)
            
            if event_type:
                raw_event["timestamp"] = int(now_dt.timestamp())
                return {
                    "source": "linux-agent",
                    "event_type": event_type,
                    "raw_event": raw_event,
                    "normalized_event": normalized_event,
                    "severity": severity,
                    "timestamp": now_dt
                }
                
        except Exception as e:
            logger.debug(f"Failed to parse auth log line: {e}")
        
        return None
