import platform
import time
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
from utils.logger import setup_logger
from api_client import BackendEventType, BackendSeverity

logger = setup_logger("windows_collector")

class WindowsEventCollector:
    def __init__(self):
        self.last_processed_timestamp: Optional[int] = None
        self.last_processed_marker: Optional[Tuple[int, int]] = None
        self._security_log_warning_emitted = False
        self.is_windows = platform.system().lower() == "windows"
        if self.is_windows:
            try:
                import win32evtlog
                import win32con
                self.win32evtlog = win32evtlog
                self.win32con = win32con
                logger.info("Windows Event Log API loaded successfully")
            except ImportError:
                logger.warning("pywin32 not installed, Windows event collection will be simulated")
                self.win32evtlog = None
                self.win32con = None

    def collect_events(self) -> List[Dict[str, Any]]:
        if not self.is_windows or not self.win32evtlog:
            return self._simulate_events()
        
        events = []
        hand = None
        try:
            # Open Security event log
            hand = self.win32evtlog.OpenEventLog(None, "Security")
            
            # Read events in reverse order
            flags = self.win32evtlog.EVENTLOG_BACKWARDS_READ | self.win32evtlog.EVENTLOG_SEQUENTIAL_READ
            total = self.win32evtlog.GetNumberOfEventLogRecords(hand)
            
            events_read = 0
            while True:
                raw_events = self.win32evtlog.ReadEventLog(hand, flags, 0)
                if not raw_events:
                    break
                
                for event in raw_events:
                    event_id = event.EventID & 0xFFFF  # Mask to get the actual event ID
                    if event_id in [4624, 4625, 4688]:
                        parsed_event = self._parse_windows_event(event, event_id)
                        if parsed_event:
                            events.append(parsed_event)
                
                events_read += len(raw_events)
                if events_read >= 100 or events_read >= total:
                    break
            
            # Sort events by Windows event position and only send events newer
            # than the last successful collection cycle. This keeps repeated
            # polling from resending the same latest 100 Security events.
            events.sort(key=self._event_marker)
            if self.last_processed_marker is not None:
                events = [item for item in events if self._event_marker(item) > self.last_processed_marker]
            if events:
                self.last_processed_marker = self._event_marker(events[-1])
            
        except Exception as e:
            if not self._security_log_warning_emitted:
                logger.warning(
                    "Windows Security event log is unavailable (%s). "
                    "Run the collector with Event Log Reader permissions to collect real Security events; "
                    "using simulated telemetry meanwhile.",
                    e,
                )
                self._security_log_warning_emitted = True
            # Fall back to simulation when privileges are insufficient
            return self._simulate_events()
        finally:
            if hand is not None:
                try:
                    self.win32evtlog.CloseEventLog(hand)
                except Exception:
                    logger.debug("Failed to close Windows event log handle", exc_info=True)
        
        return events if events else self._simulate_events()

    def _parse_windows_event(self, event, event_id: int) -> Optional[Dict[str, Any]]:
        try:
            timestamp_dt = self._event_time_to_utc(event.TimeGenerated)
            raw_event = {
                "timestamp": int(timestamp_dt.timestamp()),
                "event_id": event_id
            }
            record_number = getattr(event, "RecordNumber", None)
            if record_number is not None:
                raw_event["record_number"] = int(record_number)
                raw_event["RecordNumber"] = int(record_number)
            normalized_event = {}
            event_type = ""
            severity = BackendSeverity.MEDIUM
            
            if event_id == 4688:
                # Process creation
                event_type = BackendEventType.PROCESS
                process_name = "unknown.exe"
                command_line = ""
                string_inserts = getattr(event, "StringInserts", None) or []
                
                if len(string_inserts) >= 6:
                    process_name = string_inserts[5]
                    command_line = string_inserts[8] if len(string_inserts) >= 9 else ""
                parent_process = string_inserts[13] if len(string_inserts) >= 14 else ""
                
                raw_event["process"] = process_name
                raw_event["command_line"] = command_line
                raw_event["Image"] = process_name
                raw_event["CommandLine"] = command_line
                if parent_process:
                    raw_event["parent_process"] = parent_process
                    raw_event["ParentImage"] = parent_process
                normalized_event["process"] = process_name
                normalized_event["image"] = process_name
                normalized_event["command"] = command_line
                normalized_event["command_line"] = command_line
                if parent_process:
                    normalized_event["parent_process"] = parent_process
                
                # Check for suspicious processes
                suspicious = ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "powershell_ise.exe"]
                if any(s.lower() in process_name.lower() for s in suspicious):
                    severity = BackendSeverity.HIGH
                    
            elif event_id == 4624:
                # Successful login
                event_type = BackendEventType.LOGIN
                username = "unknown"
                if hasattr(event, 'StringInserts') and len(event.StringInserts) >= 6:
                    username = event.StringInserts[5]
                raw_event["user"] = username
                raw_event["status"] = "success"
                normalized_event["status"] = "success"
                normalized_event["user"] = username
                    
            elif event_id == 4625:
                # Failed login
                event_type = BackendEventType.LOGIN
                severity = BackendSeverity.HIGH
                username = "unknown"
                if hasattr(event, 'StringInserts') and len(event.StringInserts) >= 6:
                    username = event.StringInserts[5]
                raw_event["user"] = username
                raw_event["status"] = "failure"
                normalized_event["status"] = "failure"
                normalized_event["user"] = username
            
            if event_type:
                return {
                    "source": "windows-agent",
                    "event_type": event_type,
                    "raw_event": raw_event,
                    "normalized_event": normalized_event,
                    "severity": severity,
                    "timestamp": timestamp_dt
                }
                
        except Exception:
            logger.exception("Failed to parse Windows event")
            
        return None

    def _event_marker(self, event_payload: Dict[str, Any]) -> Tuple[int, int]:
        raw_event = event_payload.get("raw_event") or {}
        timestamp = event_payload.get("timestamp")
        if isinstance(timestamp, datetime):
            timestamp_value = int(timestamp.timestamp())
        else:
            timestamp_value = int(raw_event.get("timestamp") or 0)
        record_number = int(raw_event.get("record_number") or raw_event.get("RecordNumber") or 0)
        return timestamp_value, record_number

    def _event_time_to_utc(self, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.astimezone(timezone.utc)
        return value.astimezone(timezone.utc)

    def _simulate_events(self) -> List[Dict[str, Any]]:
        if not hasattr(self, '_last_sim_time'):
            self._last_sim_time = time.time() - 30  # 30s back
        
        events = []
        now = time.time()
        now_dt = datetime.now(timezone.utc)
        
        if now - self._last_sim_time > 10:  # Simulate every 10s
            self._last_sim_time = now
            events.append({
                "source": "windows-agent",
                "event_type": BackendEventType.PROCESS,
                "raw_event": {
                    "timestamp": int(now),
                    "process": "powershell.exe",
                    "command_line": "powershell -NoProfile -Command Get-ChildItem"
                },
                "normalized_event": {
                    "process": "powershell.exe",
                    "command": "powershell -NoProfile -Command Get-ChildItem"
                },
                "severity": BackendSeverity.HIGH,
                "timestamp": now_dt
            })
        
        return events
