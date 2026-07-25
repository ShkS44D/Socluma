from datetime import datetime, timedelta, timezone
from pathlib import Path

from event_collector.windows import WindowsEventCollector
from api_client import BackendEventType, BackendSeverity


class FakeWindowsEvent:
    EventID = 4688
    RecordNumber = 1001
    TimeGenerated = datetime(2026, 7, 5, 12, 0, 0, tzinfo=timezone.utc)
    StringInserts = [
        "S-1-5-21-1000",
        "analyst",
        "WORKSTATION",
        "0x1519602b",
        "0xb68",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "%%1938",
        "0x5bc",
        r"powershell.exe -EncodedCommand ZQBjAGgAbwAgACIAVABlAHMAdAAiAA==",
        "S-1-0-0",
        "-",
        "-",
        "0x0",
        r"C:\Windows\explorer.exe",
        "S-1-16-8192",
    ]


class FakeUsbEvent:
    EventID = 6416
    RecordNumber = 2001
    TimeGenerated = datetime(2026, 7, 25, 12, 0, 0, tzinfo=timezone.utc)
    SourceName = "Microsoft-Windows-Security-Auditing"
    ComputerName = "analyst-workstation"
    EventCategory = 0
    EventType = 8
    StringInserts = [
        "S-1-5-18",
        "SYSTEM",
        "WORKGROUP",
        "0x3e7",
        r"USBSTOR\DISK&VEN_TEST",
        "USB Mass Storage Device",
        "{4d36e967-e325-11ce-bfc1-08002be10318}",
        "DiskDrive",
        "USB\\VID_1234",
        "USBSTOR\\Disk",
        "Port_#0001.Hub_#0001",
    ]


class FakeGenericSecurityEvent:
    EventID = 1102
    RecordNumber = 2002
    TimeGenerated = datetime(2026, 7, 25, 12, 1, 0, tzinfo=timezone.utc)
    SourceName = "Microsoft-Windows-Eventlog"
    ComputerName = "analyst-workstation"
    EventCategory = 0
    EventType = 8
    StringInserts = ["analyst", "WORKGROUP"]


def make_generic_event(record_number: int, event_id: int = 4688):
    event = FakeGenericSecurityEvent()
    event.RecordNumber = record_number
    event.EventID = event_id
    event.TimeGenerated = datetime(2026, 7, 25, 12, 0, 0, tzinfo=timezone.utc) + timedelta(
        seconds=record_number
    )
    if event_id == 6416:
        event.StringInserts = list(FakeUsbEvent.StringInserts)
    return event


class FakeWin32EventLog:
    EVENTLOG_BACKWARDS_READ = 0x0008
    EVENTLOG_FORWARDS_READ = 0x0004
    EVENTLOG_SEQUENTIAL_READ = 0x0001
    EVENTLOG_SEEK_READ = 0x0002

    def __init__(self, events):
        self.events = events

    def OpenEventLog(self, _server, _channel):
        return {"read": False}

    def GetNumberOfEventLogRecords(self, _handle):
        return len(self.events)

    def GetOldestEventLogRecord(self, _handle):
        return min(event.RecordNumber for event in self.events)

    def ReadEventLog(self, handle, flags, offset):
        if handle["read"]:
            return []
        handle["read"] = True
        if flags & self.EVENTLOG_SEEK_READ:
            return [event for event in self.events if event.RecordNumber >= offset]
        return list(reversed(self.events[-100:]))

    def CloseEventLog(self, _handle):
        return None


def test_windows_4688_parser_uses_windows_11_string_insert_indexes():
    collector = WindowsEventCollector()

    parsed = collector._parse_windows_event(FakeWindowsEvent(), 4688)

    assert parsed is not None
    assert parsed["event_type"] == BackendEventType.PROCESS
    assert parsed["severity"] == BackendSeverity.HIGH
    assert parsed["raw_event"]["process"].endswith(r"powershell.exe")
    assert parsed["raw_event"]["Image"].endswith(r"powershell.exe")
    assert "EncodedCommand" in parsed["raw_event"]["command_line"]
    assert parsed["raw_event"]["CommandLine"] == parsed["raw_event"]["command_line"]
    assert parsed["raw_event"]["ParentImage"] == r"C:\Windows\explorer.exe"
    assert parsed["raw_event"]["RecordNumber"] == 1001
    assert parsed["normalized_event"]["image"] == parsed["raw_event"]["process"]
    assert parsed["normalized_event"]["command_line"] == parsed["raw_event"]["command_line"]


def test_windows_event_time_is_converted_to_utc_from_local_naive_time():
    collector = WindowsEventCollector()
    local_time = datetime.now().astimezone().replace(microsecond=0)
    naive_windows_time = local_time.replace(tzinfo=None)

    converted = collector._event_time_to_utc(naive_windows_time)

    assert converted.tzinfo == timezone.utc
    assert abs(converted - local_time.astimezone(timezone.utc)) < timedelta(seconds=1)


def test_windows_event_marker_uses_timestamp_and_record_number():
    collector = WindowsEventCollector()
    first = collector._parse_windows_event(FakeWindowsEvent(), 4688)
    second_event = FakeWindowsEvent()
    second_event.RecordNumber = 1002
    second = collector._parse_windows_event(second_event, 4688)

    assert first is not None
    assert second is not None
    assert collector._event_marker(second) > collector._event_marker(first)


def test_windows_6416_parser_exposes_usb_fields_for_custom_rules():
    collector = WindowsEventCollector()

    parsed = collector._parse_windows_event(FakeUsbEvent(), 6416)

    assert parsed is not None
    assert parsed["event_type"] == BackendEventType.FILE
    assert parsed["raw_event"]["EventID"] == 6416
    assert parsed["raw_event"]["ClassName"] == "DiskDrive"
    assert parsed["raw_event"]["DeviceId"].startswith("USBSTOR")
    assert parsed["normalized_event"]["device_class_name"] == "DiskDrive"
    assert parsed["normalized_event"]["hostname"] == "analyst-workstation"


def test_unknown_windows_security_event_is_preserved_for_custom_rules():
    collector = WindowsEventCollector()

    parsed = collector._parse_windows_event(FakeGenericSecurityEvent(), 1102)

    assert parsed is not None
    assert parsed["event_type"] == BackendEventType.ALERT
    assert parsed["raw_event"]["EventID"] == 1102
    assert parsed["raw_event"]["StringInserts"] == ["analyst", "WORKGROUP"]
    assert parsed["normalized_event"]["event_id"] == 1102


def test_incremental_cursor_does_not_lose_event_beyond_newest_100():
    collector = WindowsEventCollector()
    initial_events = [make_generic_event(record_number) for record_number in range(1, 201)]
    fake_log = FakeWin32EventLog(initial_events)
    collector.win32evtlog = fake_log

    first = collector.collect_events()
    assert len(first) == 100
    assert collector.last_processed_marker[0] == 200

    fake_log.events.extend(
        make_generic_event(record_number, 6416 if record_number == 250 else 4688)
        for record_number in range(201, 352)
    )
    second = collector.collect_events()

    assert len(second) == 151
    assert any(event["raw_event"]["EventID"] == 6416 for event in second)
    assert collector.last_processed_marker[0] == 351


def test_windows_6416_xml_preserves_system_eventdata_and_original_xml():
    collector = WindowsEventCollector()
    xml = (
        Path(__file__).parent / "tests" / "fixtures" / "windows_security_6416.xml"
    ).read_text(encoding="utf-8")

    parsed = collector._parse_event_xml(xml)

    assert parsed is not None
    assert parsed["event_type"] == BackendEventType.FILE
    assert parsed["raw_event"]["EventID"] == 6416
    assert parsed["raw_event"]["Channel"] == "Security"
    assert parsed["raw_event"]["ProviderName"] == "Microsoft-Windows-Security-Auditing"
    assert parsed["raw_event"]["EventRecordID"] == 9025000
    assert parsed["raw_event"]["EventData"]["ClassName"] == "DiskDrive"
    assert parsed["raw_event"]["DeviceId"].startswith("USBSTOR")
    assert parsed["raw_event"]["EventXML"] == xml
    assert parsed["normalized_event"]["device_id"].startswith("USBSTOR")
    assert parsed["normalized_event"]["channel"] == "Security"
