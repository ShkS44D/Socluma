from src.services.sigma_rule_service import sigma_rule_service


def windows_event(channel="Security"):
    return {
        "source": "windows-agent",
        "event_type": "file",
        "product": "windows",
        "channel": channel,
        "raw_data": {
            "EventID": "6416",
            "Channel": channel,
            "ProviderName": "Microsoft-Windows-Security-Auditing",
            "EventData": {
                "DeviceId": r"USBSTOR\Disk&Ven_Example",
                "ClassName": "DiskDrive",
                "NewProcessName": r"C:\Windows\System32\cmd.exe",
            },
        },
        "normalized_event": {"platform": "Windows", "channel": channel},
    }


def rule(detection, logsource=None):
    return {
        "title": "Test rule",
        "logsource": logsource or {"product": "windows", "service": "security"},
        "detection": detection,
    }


def test_usb_rule_matches_nested_event_data_and_integer_string_event_id():
    content = rule({
        "selection": {"EventID": 6416, "DeviceId|contains": "USBSTOR"},
        "condition": "selection",
    })
    explanation = sigma_rule_service.explain(content, windows_event())
    assert explanation["matched"]
    fields = explanation["selections"][0]["fields"]
    assert {item["resolved_from"] for item in fields} == {
        "raw_data.EventID", "raw_data.EventData.DeviceId"
    }


def test_classname_fallback_and_case_insensitive_windows_fields():
    content = rule({
        "selection": {"eventid": "6416", "classname": "diskdrive"},
        "condition": "selection",
    })
    assert sigma_rule_service.explain(content, windows_event())["matched"]


def test_modifiers_lists_and_all_semantics():
    content = rule({
        "selection1": {"DeviceId|startswith": "USB", "DeviceId|endswith": "Example"},
        "selection2": {"DeviceId|contains|all": ["USBSTOR", "Ven_"]},
        "condition": "selection1 and selection2",
    })
    assert sigma_rule_service.explain(content, windows_event())["matched"]


def test_boolean_not_parentheses_and_selection_wildcards():
    content = rule({
        "selection_usb": {"DeviceId|contains": "USBSTOR"},
        "selection_disk": {"ClassName": "DiskDrive"},
        "filter_system": {"Channel": "System"},
        "condition": "(all of selection*) and not filter_system",
    })
    assert sigma_rule_service.explain(content, windows_event())["matched"]


def test_security_rule_does_not_match_system_channel():
    content = rule({
        "selection": {"EventID": 6416},
        "condition": "selection",
    })
    explanation = sigma_rule_service.explain(content, windows_event("System"))
    assert not explanation["matched"]
    assert not explanation["logsource"]["matched"]


def test_validation_generates_id_and_rejects_unsupported_modifier_and_condition():
    valid = sigma_rule_service.validate(rule({
        "selection": {"EventID": 6416},
        "condition": "selection",
    }))
    assert valid.valid
    assert valid.normalized["id"]

    unsupported_modifier = sigma_rule_service.validate(rule({
        "selection": {"DeviceId|base64": "USBSTOR"},
        "condition": "selection",
    }))
    assert not unsupported_modifier.valid
    assert "unsupported modifier" in " ".join(unsupported_modifier.errors).lower()

    unsupported_condition = sigma_rule_service.validate(rule({
        "selection": {"EventID": 6416},
        "condition": "selection near other",
    }))
    assert not unsupported_condition.valid
