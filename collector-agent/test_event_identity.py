from collector import TriageOpsCollector


def _windows_payload(record_number: int, channel: str = "Security", host: str = "saad-pc"):
    return {
        "source": "windows-agent",
        "event_type": "login",
        "raw_event": {
            "EventID": 4624,
            "EventRecordID": record_number,
            "Channel": channel,
            "Computer": host,
        },
        "normalized_event": {
            "event_id": 4624,
            "channel": channel,
            "hostname": host,
        },
    }


def test_repeated_windows_event_ids_use_unique_record_identity():
    first = TriageOpsCollector._derive_source_event_id(_windows_payload(1001))
    second = TriageOpsCollector._derive_source_event_id(_windows_payload(1002))

    assert first == "windows:saad-pc:Security:1001"
    assert second == "windows:saad-pc:Security:1002"
    assert first != second


def test_windows_record_identity_includes_channel_and_host():
    security = TriageOpsCollector._derive_source_event_id(_windows_payload(1001, "Security", "saad-pc"))
    system = TriageOpsCollector._derive_source_event_id(_windows_payload(1001, "System", "saad-pc"))
    other_host = TriageOpsCollector._derive_source_event_id(_windows_payload(1001, "Security", "other-pc"))

    assert len({security, system, other_host}) == 3


def test_event_kind_is_not_used_as_a_unique_record_id():
    payload = {
        "source": "windows-agent",
        "raw_event": {"EventID": 4624},
        "normalized_event": {"event_id": 4624},
    }

    assert TriageOpsCollector._derive_source_event_id(payload) is None
