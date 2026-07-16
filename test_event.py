import requests
import json

BASE_URL = "http://localhost:8001"

# First login to get a token
login_url = f"{BASE_URL}/api/v1/auth/login"
login_data = {
    "email": "saad@test.com",
    "password": "Admin@12345"
}

login_response = requests.post(login_url, json=login_data)
print("Login Response Status:", login_response.status_code)
print("Login Response:", login_response.text)

if login_response.status_code == 200:
    token = login_response.json()["access_token"]
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    # Now send an ingest event
    ingest_url = f"{BASE_URL}/api/v1/events/ingest"
    ingest_data = {
        "source": "windows-edr",
        "event_type": "process",
        "raw_event": {
            "process": "powershell.exe",
            "command": "powershell -enc SGVsbG8="
        },
        "normalized_event": {
            "process": "powershell.exe",
            "command": "powershell -enc SGVsbG8="
        }
    }

    print("\nSending ingest event...")
    try:
        response = requests.post(ingest_url, json=ingest_data, headers=headers, timeout=30)
        print("Ingest Response Status:", response.status_code)
        print("Response Text:", json.dumps(response.json(), indent=2) if response.status_code != 500 else response.text)
    except Exception as e:
        print(f"Error sending request: {e}")
