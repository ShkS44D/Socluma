from datetime import datetime, timedelta, timezone

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
