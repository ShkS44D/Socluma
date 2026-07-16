
import requests
import json
import time
import os

BASE_URL = "http://localhost:8001/api/v1"

# Step 1: Login to get JWT token
login_payload = {
    "email": os.environ["E2E_EMAIL"],
    "password": os.environ["E2E_PASSWORD"]
}
login_response = requests.post(f"{BASE_URL}/auth/login", json=login_payload)
if login_response.status_code != 200:
    print(f"Login failed: {login_response.status_code}, {login_response.text}")
    exit(1)
token = login_response.json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}
print("Successfully logged in!")

# Step 2: Send test event 1 - Suspicious PowerShell Execution (should trigger rule 1)
test_event1 = {
    "source": "test-collector",
    "event_type": "process",
    "raw_event": {
        "process": "powershell.exe",
        "command": "powershell -enc SGVsbG8gV29ybGQh",
        "user": "SYSTEM"
    }
}
print("\nSending PowerShell test event...")
ingest1_response = requests.post(f"{BASE_URL}/events/ingest", json=test_event1, headers=headers)
print(f"Ingest 1 response status: {ingest1_response.status_code}")
if ingest1_response.status_code != 200:
    print(f"Ingest failed: {ingest1_response.text}")
else:
    print("Ingested test event 1!")

# Wait 2 seconds
time.sleep(2)

# Step 3: Check events endpoint
print("\nChecking events endpoint...")
events_response = requests.get(f"{BASE_URL}/events", headers=headers)
if events_response.status_code == 200:
    print("Events found:")
    print(json.dumps(events_response.json(), indent=2))
else:
    print(f"Failed to get events: {events_response.status_code}, {events_response.text}")

# Step 4: Check alerts endpoint
print("\nChecking alerts endpoint...")
alerts_response = requests.get(f"{BASE_URL}/alerts", headers=headers)
if alerts_response.status_code == 200:
    print("Alerts found:")
    print(json.dumps(alerts_response.json(), indent=2))
else:
    print(f"Failed to get alerts: {alerts_response.status_code}, {alerts_response.text}")

# Step 5: Check incidents endpoint
print("\nChecking incidents endpoint...")
incidents_response = requests.get(f"{BASE_URL}/incidents", headers=headers)
if incidents_response.status_code == 200:
    print("Incidents found:")
    print(json.dumps(incidents_response.json(), indent=2))
else:
    print(f"Failed to get incidents: {incidents_response.status_code}, {incidents_response.text}")

print("\nTest complete!")
