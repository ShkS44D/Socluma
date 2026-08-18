import platform
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
from utils.logger import setup_logger
from api_client import BackendEventType, BackendSeverity

logger = setup_logger("windows_collector")

class WindowsEventCollector:
    INITIAL_EVENT_LIMIT = 100
    MAX_EVENTS_PER_POLL = 1000

    def __init__(self, channels=None):
        self.last_processed_timestamp: Optional[int] = None
        self.last_processed_marker: Optional[Tuple[int, int]] = None
        self.channels = tuple(channels or ("Security", "System", "Application"))
        self.channel_cursors: Dict[str, int] = {}
        self._unavailable_channels: set[str] = set()
        self._security_log_warning_emitted = False
        self.is_windows = platform.system().lower() == "windows"
        if self.is_windows:
            try:
                import win32evtlog
                import win32con
                self.win32evtlog = win32evtlog
                self.win32con = win32con
                logger.info("Windows Event Log API loaded successfully")
                self._warn_if_pnp_auditing_disabled()
            except ImportError:
                logger.warning("pywin32 not installed, Windows event collection will be simulated")
                self.win32evtlog = None
                self.win32con = None

    def collect_events(self) -> List[Dict[str, Any]]:
        if not self.is_windows or not self.win32evtlog:
            return self._simulate_events()
        if hasattr(self.win32evtlog, "EvtQuery") and hasattr(self.win32evtlog, "EvtRender"):
            return self._collect_xml_events()
        return self._collect_legacy_security_events()

    def _collect_xml_events(self) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        for channel in self.channels:
            query_handle = None
            try:
                cursor = self.channel_cursors.get(channel)
                if cursor is None:
                    query = "*"
                    flags = (
                        self.win32evtlog.EvtQueryChannelPath
                        | self.win32evtlog.EvtQueryReverseDirection
                    )
                    limit = self.INITIAL_EVENT_LIMIT
                else:
                    query = f"*[System[EventRecordID > {int(cursor)}]]"
                    flags = self.win32evtlog.EvtQueryChannelPath
                    limit = self.MAX_EVENTS_PER_POLL
                query_handle = self.win32evtlog.EvtQuery(channel, flags, query)
                channel_events = []
                while len(channel_events) < limit:
                    batch_size = min(64, limit - len(channel_events))
                    try:
                        handles = self.win32evtlog.EvtNext(query_handle, batch_size)
                    except Exception as exc:
                        if getattr(exc, "winerror", None) == 259:
                            break
                        raise
                    if not handles:
                        break
                    for event_handle in handles:
                        try:
                            xml = self.win32evtlog.EvtRender(
                                event_handle, self.win32evtlog.EvtRenderEventXml
                            )
                            parsed = self._parse_event_xml(xml)
                            if parsed:
                                channel_events.append(parsed)
                        finally:
                            if hasattr(self.win32evtlog, "EvtClose"):
                                self.win32evtlog.EvtClose(event_handle)
                channel_events.sort(key=self._event_marker)
                if channel_events:
                    self.channel_cursors[channel] = max(
                        int(item["raw_event"].get("EventRecordID") or 0)
                        for item in channel_events
                    )
                    events.extend(channel_events)
                logger.info(
                    "Windows channel poll completed (channel=%s events_read=%s cursor=%s)",
                    channel,
                    len(channel_events),
                    self.channel_cursors.get(channel),
                )
            except Exception as exc:
                if channel not in self._unavailable_channels:
                    logger.warning(
                        "Windows event channel unavailable (channel=%s error=%s). "
                        "This warning will not repeat until the collector restarts.",
                        channel,
                        exc,
                    )
                    self._unavailable_channels.add(channel)
            finally:
                if query_handle is not None and hasattr(self.win32evtlog, "EvtClose"):
                    self.win32evtlog.EvtClose(query_handle)
        events.sort(key=lambda item: (item["timestamp"], self._event_marker(item)))
        return events

    def _collect_legacy_security_events(self) -> List[Dict[str, Any]]:
        
        events = []
        hand = None
        try:
            # Open Security event log
            hand = self.win32evtlog.OpenEventLog(None, "Security")
            
            total = self.win32evtlog.GetNumberOfEventLogRecords(hand)
            oldest_record = self.win32evtlog.GetOldestEventLogRecord(hand) if total else 0
            last_record = self.last_processed_marker[0] if self.last_processed_marker else None
            if last_record is not None and (
                last_record < oldest_record or last_record >= oldest_record + total
            ):
                logger.info("Windows Security log was cleared or rotated; resetting collection cursor")
                self.last_processed_marker = None
                last_record = None

            events_read = 0
            first_read = True
            initial_collection = last_record is None
            while True:
                if initial_collection:
                    flags = (
                        self.win32evtlog.EVENTLOG_BACKWARDS_READ
                        | self.win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    )
                    offset = 0
                elif first_read:
                    flags = (
                        self.win32evtlog.EVENTLOG_FORWARDS_READ
                        | self.win32evtlog.EVENTLOG_SEEK_READ
                    )
                    offset = last_record + 1
                else:
                    flags = (
                        self.win32evtlog.EVENTLOG_FORWARDS_READ
                        | self.win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    )
                    offset = 0

                raw_events = self.win32evtlog.ReadEventLog(hand, flags, offset)
                if not raw_events:
                    break
                first_read = False

                for event in raw_events:
                    event_id = event.EventID & 0xFFFF  # Mask to get the actual event ID
                    parsed_event = self._parse_windows_event(event, event_id)
                    if parsed_event:
                        events.append(parsed_event)
                
                events_read += len(raw_events)
                event_limit = self.INITIAL_EVENT_LIMIT if initial_collection else self.MAX_EVENTS_PER_POLL
                if events_read >= event_limit or events_read >= total:
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

    def _parse_event_xml(self, xml: str) -> Optional[Dict[str, Any]]:
        try:
            root = ET.fromstring(xml)
            namespace = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
            system_node = root.find("e:System", namespace)
            if system_node is None:
                return None

            def text(path: str) -> Optional[str]:
                node = system_node.find(path, namespace)
                return node.text if node is not None else None

            provider_node = system_node.find("e:Provider", namespace)
            time_node = system_node.find("e:TimeCreated", namespace)
            execution_node = system_node.find("e:Execution", namespace)
            security_node = system_node.find("e:Security", namespace)
            event_id = int(text("e:EventID") or 0)
            record_id = int(text("e:EventRecordID") or 0)
            channel = text("e:Channel") or "Unknown"
            timestamp_dt = self._parse_system_time(
                time_node.attrib.get("SystemTime") if time_node is not None else None
            )
            event_data: Dict[str, Any] = {}
            unnamed_values = []
            event_data_node = root.find("e:EventData", namespace)
            if event_data_node is not None:
                for data_node in event_data_node.findall("e:Data", namespace):
                    value = data_node.text or ""
                    name = data_node.attrib.get("Name")
                    if name:
                        event_data[name] = value
                    else:
                        unnamed_values.append(value)
            user_data_node = root.find("e:UserData", namespace)
            if user_data_node is not None:
                for node in user_data_node.iter():
                    if node is user_data_node:
                        continue
                    key = node.tag.rsplit("}", 1)[-1]
                    if node.text and node.text.strip():
                        event_data.setdefault(key, node.text.strip())
            if unnamed_values:
                event_data["Values"] = unnamed_values

            system = {
                "ProviderName": provider_node.attrib.get("Name") if provider_node is not None else None,
                "ProviderGuid": provider_node.attrib.get("Guid") if provider_node is not None else None,
                "EventID": event_id,
                "Version": text("e:Version"),
                "Level": text("e:Level"),
                "Task": text("e:Task"),
                "Opcode": text("e:Opcode"),
                "Keywords": text("e:Keywords"),
                "EventRecordID": record_id,
                "Channel": channel,
                "Computer": text("e:Computer"),
                "ProcessID": execution_node.attrib.get("ProcessID") if execution_node is not None else None,
                "ThreadID": execution_node.attrib.get("ThreadID") if execution_node is not None else None,
                "UserID": security_node.attrib.get("UserID") if security_node is not None else None,
                "TimeCreated": timestamp_dt.isoformat(),
            }
            raw_event = {
                **{key: value for key, value in system.items() if value is not None},
                **event_data,
                "System": system,
                "EventData": event_data,
                "event_data": event_data,
                "EventXML": xml,
                "event_id": event_id,
                "record_number": record_id,
                "log_name": channel,
                "channel": channel,
                "provider_name": system.get("ProviderName"),
                "timestamp": int(timestamp_dt.timestamp()),
            }
            normalized_event = {
                "event_id": event_id,
                "hostname": system.get("Computer"),
                "channel": channel,
                "log_name": channel,
                "provider_name": system.get("ProviderName"),
                "operating_system": "windows",
                "platform": "windows",
                "product": "windows",
                "event_data": event_data,
            }
            for key, value in event_data.items():
                normalized_event.setdefault(self._snake_case(key), value)
            return {
                "source": "windows-agent",
                "event_type": self._event_type_for(event_id, channel),
                "raw_event": raw_event,
                "normalized_event": normalized_event,
                "severity": self._severity_for(event_id, system.get("Level")),
                "timestamp": timestamp_dt,
            }
        except Exception:
            logger.exception("Failed to parse Windows Event XML")
            return None

    def _parse_system_time(self, value: Optional[str]) -> datetime:
        if not value:
            return datetime.now(timezone.utc)
        normalized = value.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized).astimezone(timezone.utc)

    def _event_type_for(self, event_id: int, channel: str) -> str:
        if event_id == 4688:
            return BackendEventType.PROCESS
        if event_id in {4624, 4625}:
            return BackendEventType.LOGIN
        if event_id == 6416:
            return BackendEventType.FILE
        return BackendEventType.ALERT

    def _severity_for(self, event_id: int, level: Optional[str]) -> str:
        if event_id in {4625, 4688}:
            return BackendSeverity.HIGH
        if str(level) in {"1", "2"}:
            return BackendSeverity.HIGH
        return BackendSeverity.MEDIUM

    def _snake_case(self, value: str) -> str:
        import re
        value = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", value)
        return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value).lower()

    def _warn_if_pnp_auditing_disabled(self) -> None:
        try:
            result = subprocess.run(
                ["auditpol", "/get", "/subcategory:Plug and Play Events"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            output = f"{result.stdout}\n{result.stderr}".strip()
            if result.returncode != 0:
                logger.warning(
                    "Unable to verify Plug and Play audit policy; Event 6416 requires successful Audit PNP Activity auditing"
                )
            elif "No Auditing" in output or "Success" not in output:
                logger.warning(
                    "Plug and Play success auditing appears disabled; Event 6416 will not be generated until an administrator enables it"
                )
        except Exception:
            logger.warning(
                "Unable to verify Plug and Play audit policy; Event 6416 requires successful Audit PNP Activity auditing"
            )

    def _parse_windows_event(self, event, event_id: int) -> Optional[Dict[str, Any]]:
        try:
            timestamp_dt = self._event_time_to_utc(event.TimeGenerated)
            raw_event = {
                "timestamp": int(timestamp_dt.timestamp()),
                "event_id": event_id,
                "EventID": event_id,
            }
            source_name = getattr(event, "SourceName", None)
            computer = getattr(event, "ComputerName", None)
            category = getattr(event, "EventCategory", None)
            event_type_code = getattr(event, "EventType", None)
            string_inserts = list(getattr(event, "StringInserts", None) or [])
            if source_name:
                raw_event["SourceName"] = str(source_name)
            if computer:
                raw_event["Computer"] = str(computer)
            if category is not None:
                raw_event["EventCategory"] = int(category)
            if event_type_code is not None:
                raw_event["WindowsEventType"] = int(event_type_code)
            if string_inserts:
                raw_event["StringInserts"] = [str(value) for value in string_inserts]
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

            elif event_id == 6416:
                # Security auditing: a new external Plug and Play device was
                # recognized. Field order follows the Microsoft 6416 schema.
                event_type = BackendEventType.FILE
                severity = BackendSeverity.MEDIUM
                field_names = [
                    "SubjectUserSid",
                    "SubjectUserName",
                    "SubjectDomainName",
                    "SubjectLogonId",
                    "DeviceId",
                    "DeviceDescription",
                    "ClassId",
                    "ClassName",
                    "VendorIds",
                    "CompatibleIds",
                    "LocationInformation",
                ]
                for index, field_name in enumerate(field_names):
                    if index < len(string_inserts):
                        raw_event[field_name] = str(string_inserts[index])

                normalized_event["event_id"] = event_id
                normalized_event["device_id"] = raw_event.get("DeviceId")
                normalized_event["device_description"] = raw_event.get("DeviceDescription")
                normalized_event["device_class_id"] = raw_event.get("ClassId")
                normalized_event["device_class_name"] = raw_event.get("ClassName")
                normalized_event["vendor_ids"] = raw_event.get("VendorIds")
                normalized_event["compatible_ids"] = raw_event.get("CompatibleIds")
                normalized_event["location"] = raw_event.get("LocationInformation")

            else:
                # Preserve arbitrary Windows Security events so tenant-authored
                # Sigma rules can match EventID and the fields exposed by the
                # legacy Windows Event Log API.
                event_type = BackendEventType.ALERT
                severity = BackendSeverity.MEDIUM
                normalized_event["event_id"] = event_id

            if computer:
                normalized_event["hostname"] = str(computer)
            
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
        # The Windows record number is the reliable ingestion cursor. Event
        # timestamps remain part of the marker only as a deterministic
        # tiebreaker and are not trusted to be strictly monotonic.
        return record_number, timestamp_value

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
