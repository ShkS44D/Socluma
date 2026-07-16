"""End-to-end SOC workflow verification script."""
import requests
import sys

BASE = "http://localhost:8001/api/v1"
EMAIL = "saad@test.com"
PASSWORD = "Admin@12345"


def main():
    # 1. Login
    r = requests.post(f"{BASE}/auth/login", json={"email": EMAIL, "password": PASSWORD}, timeout=30)
    print(f"LOGIN: {r.status_code}")
    if r.status_code != 200:
        print(r.text)
        sys.exit(1)
    token = r.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Health check
    r = requests.get("http://localhost:8001/health", timeout=10)
    print(f"HEALTH: {r.status_code} {r.json()}")

    # 3. Run full attack chain simulation
    r = requests.post(f"{BASE}/events/simulate/full_attack_chain", headers=headers, timeout=120)
    print(f"SIMULATE: {r.status_code}")
    if r.status_code != 201:
        print(r.text)
        sys.exit(1)
    events = r.json()
    print(f"Events ingested: {len(events)}")
    for e in events:
        det_count = len(e.get("detections", []))
        inc_flag = e.get("incident_created")
        inc_id = (e.get("incident_id") or "-")[:8]
        print(f"  Event {e['id'][:8]}... detections={det_count} incident={inc_flag} id={inc_id}...")

    # 4. List incidents
    r = requests.get(f"{BASE}/incidents", headers=headers, timeout=30)
    incidents = r.json()["items"]
    print(f"INCIDENTS: {len(incidents)}")
    if not incidents:
        print("ERROR: No incidents created")
        sys.exit(1)

    inc = incidents[0]
    inc_id = inc["id"]
    print(f"  Title: {inc['title']}")
    print(f"  AI Summary: {(inc.get('ai_summary') or 'NONE')[:100]}")
    print(f"  Why Suspicious: {(inc.get('why_suspicious') or 'NONE')[:100]}")
    print(f"  MITRE: {inc.get('attack_technique', {}).get('technique_id', '-')}")
    print(f"  Actions: {len(inc.get('recommended_actions') or [])}")

    # 5. IOCs
    r = requests.get(f"{BASE}/incidents/{inc_id}/iocs", headers=headers, timeout=30)
    iocs = r.json()
    print(f"  IOCs: {len(iocs)}")
    for ioc in iocs[:5]:
        print(f"    {ioc['type']}: {ioc['value']}")

    # 6. Manual AI re-analyze
    r = requests.post(f"{BASE}/incidents/{inc_id}/analyze", headers=headers, timeout=120)
    print(f"AI ANALYZE: {r.status_code}")
    if r.status_code == 200:
        ai = r.json()
        print(f"  Summary: {ai['summary'][:120]}")
        print(f"  Why: {ai['why_suspicious'][:120]}")
        print(f"  MITRE: {ai['attack_technique'].get('technique_id')}")
        print(f"  Actions ({len(ai['recommended_actions'])}): {ai['recommended_actions'][:2]}")
    else:
        print(r.text)
        sys.exit(1)

    print("\n=== WORKFLOW VERIFIED: Event -> Detection -> Alert -> Incident -> IOC -> AI ===")


if __name__ == "__main__":
    main()
