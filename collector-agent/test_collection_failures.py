from unittest.mock import MagicMock

from event_collector.windows import WindowsEventCollector
from event_collector.linux import LinuxEventCollector


def test_windows_without_api_never_generates_telemetry():
    collector = WindowsEventCollector()
    collector.win32evtlog = None
    assert collector.collect_events() == []


def test_windows_on_other_platform_never_generates_telemetry():
    collector = WindowsEventCollector()
    collector.is_windows = False
    assert collector.collect_events() == []


def test_windows_empty_legacy_poll_is_empty():
    collector = WindowsEventCollector()
    collector.is_windows = True
    collector.win32evtlog = MagicMock(spec=["OpenEventLog", "GetNumberOfEventLogRecords", "ReadEventLog", "CloseEventLog",
                                          "EVENTLOG_BACKWARDS_READ", "EVENTLOG_SEQUENTIAL_READ"])
    collector.win32evtlog.EVENTLOG_BACKWARDS_READ = 8
    collector.win32evtlog.EVENTLOG_SEQUENTIAL_READ = 1
    collector.win32evtlog.GetNumberOfEventLogRecords.return_value = 0
    collector.win32evtlog.ReadEventLog.return_value = []
    assert collector.collect_events() == []


def test_windows_log_permission_failure_is_empty():
    collector = WindowsEventCollector()
    collector.is_windows = True
    collector.win32evtlog = MagicMock(spec=["OpenEventLog"])
    collector.win32evtlog.OpenEventLog.side_effect = PermissionError("denied")
    assert collector.collect_events() == []


def test_linux_missing_logs_never_generates_telemetry():
    collector = LinuxEventCollector()
    collector.is_linux = True
    collector.log_file_path = None
    assert collector.collect_events() == []


def test_linux_unreadable_logs_never_generate_telemetry(tmp_path):
    collector = LinuxEventCollector()
    collector.is_linux = True
    collector.log_file_path = str(tmp_path / "missing.log")
    assert collector.collect_events() == []
