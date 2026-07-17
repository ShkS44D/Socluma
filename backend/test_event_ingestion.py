"""Opt-in manual ingestion smoke script.

This file is named for its purpose, so pytest may discover it when invoked from
the backend directory. Keep all runtime work behind ``main`` so collection is
always side-effect free.
"""

import os
import time

import requests


BASE_URL = "http://localhost:8001/api/v1"


def main() -> int:
    email = os.getenv("E2E_EMAIL")
    password = os.getenv("E2E_PASSWORD")
    if not email or not password:
        print("E2E_EMAIL and E2E_PASSWORD are required")
        return 2

    login_response = requests.post(
        f"{BASE_URL}/auth/login",
        json={"email": email, "password": password},
    )
    if login_response.status_code != 200:
        print(f"Login failed with status {login_response.status_code}")
        return 1

    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("Successfully logged in")

    test_event = {
        "source": "test-collector",
        "event_type": "process",
        "raw_event": {
            "process": "powershell.exe",
            "command": "powershell -enc SGVsbG8gV29ybGQh",
            "user": "SYSTEM",
        },
    }
    ingest_response = requests.post(
        f"{BASE_URL}/events/ingest",
        json=test_event,
        headers=headers,
    )
    print(f"Ingest response status: {ingest_response.status_code}")
    if ingest_response.status_code != 200:
        return 1

    time.sleep(2)
    for resource in ("events", "alerts", "incidents"):
        response = requests.get(f"{BASE_URL}/{resource}", headers=headers)
        print(f"{resource.capitalize()} response status: {response.status_code}")
        if response.status_code != 200:
            return 1
        payload = response.json()
        records = payload.get("items", []) if isinstance(payload, dict) else payload
        print(f"{resource.capitalize()} returned {len(records)} record(s)")

    print("Test complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
