"""Run the deterministic Socluma demo smoke test against a running Socluma API."""

from __future__ import annotations

import argparse
import os
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx

from scripts.seed_test_demo import ANALYST_EMAIL_DEFAULT, DEMO_SLUG, OWNER_EMAIL_DEFAULT


@dataclass
class Smoke:
    client: httpx.Client
    passed: int = 0
    failed: int = 0

    @staticmethod
    def summarize(value):
        if isinstance(value, list):
            return f"{len(value)} item(s)"
        if isinstance(value, dict):
            if "status" in value and isinstance(value["status"], str):
                return value["status"]
            if "total" in value and isinstance(value["total"], int):
                return f"{value['total']} item(s)"
            return "ok"
        return value

    def check(self, name: str, operation, display=None):
        try:
            detail = operation()
            self.passed += 1
            safe_detail = display(detail) if display else self.summarize(detail)
            print(f"PASS {name}: {safe_detail}")
            return detail
        except Exception as exc:
            self.failed += 1
            print(f"FAIL {name}: {type(exc).__name__}: {exc}")
            return None

    @staticmethod
    def ok(response: httpx.Response, expected=(200,)):
        if response.status_code not in expected:
            raise RuntimeError(f"HTTP {response.status_code} ({response.text[:180]})")
        return response


def _login(client: httpx.Client, email: str, password: str) -> str:
    response = Smoke.ok(client.post("/api/v1/auth/login", json={"email": email, "password": password}))
    payload = response.json()
    if payload.get("mfa_required"):
        raise RuntimeError("MFA challenge required; complete this account's login interactively")
    token = payload.get("access_token")
    if not token:
        raise RuntimeError("Authentication response did not contain an access token")
    return token


def _switch_to_organization(client: httpx.Client, token: str, organization_slug: str) -> str:
    headers = {"Authorization": f"Bearer {token}"}
    organizations = Smoke.ok(client.get("/api/v1/organizations", headers=headers)).json()
    organization = next((row for row in organizations if row.get("slug") == organization_slug), None)
    if not organization:
        raise RuntimeError(f"Organization membership is unavailable: {organization_slug}")
    response = Smoke.ok(
        client.post(
            "/api/v1/organizations/switch",
            headers=headers,
            json={"organization_id": organization["id"]},
        )
    )
    return response.json()["access_token"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=os.getenv("SOCLUMA_BASE_URL", "http://127.0.0.1:8001"))
    parser.add_argument("--owner-email", default=os.getenv("TEST_DEMO_OWNER_EMAIL", OWNER_EMAIL_DEFAULT))
    parser.add_argument("--analyst-email", default=os.getenv("TEST_DEMO_ANALYST_EMAIL", ANALYST_EMAIL_DEFAULT))
    parser.add_argument("--organization-slug", default=os.getenv("TEST_DEMO_ORGANIZATION_SLUG", DEMO_SLUG))
    args = parser.parse_args()
    owner_password = os.getenv("TEST_DEMO_OWNER_PASSWORD", "")
    analyst_password = os.getenv("TEST_DEMO_ANALYST_PASSWORD", "")
    if not owner_password or not analyst_password:
        print("FAIL configuration: Socluma demo password environment variables are required")
        return 2

    with httpx.Client(base_url=args.base_url.rstrip("/"), timeout=30, follow_redirects=False) as client:
        smoke = Smoke(client)
        smoke.check("critical health", lambda: Smoke.ok(client.get("/health")).json()["status"])
        smoke.check("liveness health", lambda: Smoke.ok(client.get("/health/live")).json()["status"])
        smoke.check("readiness health", lambda: Smoke.ok(client.get("/health/ready")).json()["status"])
        owner_token = smoke.check(
            "owner login", lambda: _login(client, args.owner_email, owner_password),
            display=lambda _token: "authenticated",
        )
        analyst_token = smoke.check(
            "analyst login", lambda: _login(client, args.analyst_email, analyst_password),
            display=lambda _token: "authenticated",
        )
        if not owner_token or not analyst_token:
            print(f"SUMMARY {smoke.passed} passed, {smoke.failed} failed")
            return 1
        owner_token = smoke.check(
            "owner target organization switch",
            lambda: _switch_to_organization(client, owner_token, args.organization_slug),
            display=lambda _token: args.organization_slug,
        )
        analyst_token = smoke.check(
            "analyst target organization switch",
            lambda: _switch_to_organization(client, analyst_token, args.organization_slug),
            display=lambda _token: args.organization_slug,
        )
        if not owner_token or not analyst_token:
            print(f"SUMMARY {smoke.passed} passed, {smoke.failed} failed")
            return 1
        owner = {"Authorization": f"Bearer {owner_token}"}
        analyst = {"Authorization": f"Bearer {analyst_token}"}

        effective = smoke.check("active organization", lambda: Smoke.ok(client.get("/api/v1/access-control/effective", headers=owner)).json())
        if effective:
            smoke.check("tenant identity", lambda: args.organization_slug if effective.get("role") == "owner" and effective.get("organization_id") else (_ for _ in ()).throw(RuntimeError("owner organization is not active")))
        smoke.check(
            "dashboard aggregate APIs",
            lambda: {
                "events_today": Smoke.ok(client.get("/api/v1/events/stats/today", headers=owner)).json().get("count", 0),
                "incident_total": Smoke.ok(client.get("/api/v1/incidents/stats", headers=owner)).json().get("total_incidents", 0),
                "ioc_total": Smoke.ok(client.get("/api/v1/iocs/stats", headers=owner)).json().get("total_iocs", 0),
            },
        )
        collectors = smoke.check("collector status", lambda: Smoke.ok(client.get("/api/v1/collectors", headers=owner)).json())
        if collectors is not None:
            smoke.check("healthy demo collector", lambda: next(row["id"] for row in collectors if row["name"] == "demo-collector" and row["status"] == "online"))
        events = smoke.check("security events", lambda: Smoke.ok(client.get("/api/v1/events", headers=owner, params={"limit": 100})).json())
        rules = smoke.check("detection rules", lambda: Smoke.ok(client.get("/api/v1/detection-rules", headers=owner)).json())
        if rules is not None:
            smoke.check("matched demo rules", lambda: len([row for row in rules if str(row.get("name", "")).startswith("[SYNTHETIC DEMO]")]) or (_ for _ in ()).throw(RuntimeError("no demo rules")))
        alerts = smoke.check("related alerts", lambda: Smoke.ok(client.get("/api/v1/alerts", headers=owner, params={"page_size": 100})).json())
        incidents = smoke.check("correlated incident", lambda: Smoke.ok(client.get("/api/v1/incidents", headers=owner, params={"page_size": 100})).json())
        incident = None
        if incidents:
            items = incidents.get("items", incidents if isinstance(incidents, list) else [])
            incident = next((row for row in items if str(row.get("title", "")).startswith("[SYNTHETIC DEMO]")), None)
            smoke.check("evidence-backed incident present", lambda: incident["id"] if incident else (_ for _ in ()).throw(RuntimeError("demo incident missing")))
        if incident:
            explanation = smoke.check("incident explanation", lambda: Smoke.ok(client.get(f"/api/v1/incidents/{incident['id']}/explanation", headers=owner)).json())
            if explanation:
                smoke.check("MITRE progression", lambda: len(explanation.get("mitre_attack_mapping", [])) >= 2 or (_ for _ in ()).throw(RuntimeError("insufficient MITRE stages")))
                smoke.check("evidence citations", lambda: explanation.get("evidence_summary", {}).get("source_event_count", 0) >= 2 or (_ for _ in ()).throw(RuntimeError("source evidence missing")))
            fallback = smoke.check("Socluma Copilot deterministic fallback", lambda: Smoke.ok(client.post(f"/api/v1/ai/incident/{incident['id']}/summary", headers=analyst, params={"offline": "true"})).json())
            if fallback:
                smoke.check("fallback disclosure", lambda: fallback["executive_summary"].startswith("Deterministic offline analysis") or (_ for _ in ()).throw(RuntimeError("fallback not labelled")))

        iocs = smoke.check("IOC inventory and normalization", lambda: Smoke.ok(client.get("/api/v1/iocs", headers=owner, params={"page_size": 100})).json())
        ioc_items = iocs.get("items", []) if iocs else []
        smoke.check("normalized IOCs", lambda: len([row for row in ioc_items if row.get("normalized_value")]) >= 3 or (_ for _ in ()).throw(RuntimeError("normalized IOC set incomplete")))
        sightings = smoke.check("internal sightings", lambda: Smoke.ok(client.get("/api/v1/iocs/sightings", headers=owner)).json())
        watchlists = smoke.check("watchlist membership", lambda: Smoke.ok(client.get("/api/v1/iocs/watchlists", headers=owner)).json())
        hunts = smoke.check("historical hunt", lambda: Smoke.ok(client.get("/api/v1/ioc-commercial/hunts", headers=owner)).json())
        if hunts:
            smoke.check("completed bounded hunt", lambda: next(row["id"] for row in hunts["items"] if row["status"] == "completed" and not row.get("truncated")))
        drafts = [row for row in (rules or []) if row.get("lifecycle_status") == "draft" and not row.get("enabled", True)]
        smoke.check("disabled IOC detection draft", lambda: drafts[0]["id"] if drafts else (_ for _ in ()).throw(RuntimeError("draft missing")))
        recommendations = smoke.check("pending response recommendation", lambda: Smoke.ok(client.get("/api/v1/ioc-commercial/recommendations", headers=owner)).json())
        recommendation = recommendations["items"][0] if recommendations and recommendations.get("items") else None
        if recommendation:
            self_decision = client.post(
                f"/api/v1/access-control/approvals/{recommendation['approval_id']}/decision",
                headers=analyst, json={"decision": "approve"},
            )
            smoke.check("requester self-approval prevented", lambda: self_decision.status_code == 403 or (_ for _ in ()).throw(RuntimeError(f"HTTP {self_decision.status_code}")))
        audit = smoke.check("audit visibility", lambda: Smoke.ok(client.get("/api/v1/audit-logs", headers=owner, params={"limit": 50})).json())
        reports = smoke.check("completed IOC report", lambda: Smoke.ok(client.get("/api/v1/ioc-commercial/reports", headers=owner)).json())
        report = next((row for row in (reports or {}).get("items", []) if row.get("status") == "completed"), None)
        if report:
            download = client.get(f"/api/v1/ioc-commercial/reports/{report['id']}/download", headers=owner)
            smoke.check("authenticated report download", lambda: len(Smoke.ok(download).content) or (_ for _ in ()).throw(RuntimeError("empty report")))
            smoke.check("safe report filename", lambda: download.headers.get("content-disposition", "").startswith("attachment; filename=\"socluma-ioc-report-") or (_ for _ in ()).throw(RuntimeError("filename missing")))
        smoke.check("unauthenticated tenant data denied", lambda: client.get("/api/v1/iocs").status_code in {401, 403} or (_ for _ in ()).throw(RuntimeError("IOC inventory exposed")))
        hidden_id = str(uuid.uuid4())
        smoke.check(
            "cross-tenant identifier hidden",
            lambda: client.get(f"/api/v1/iocs/{hidden_id}", headers=owner).status_code == 404
            or (_ for _ in ()).throw(RuntimeError("foreign or unknown IOC identifier was not hidden")),
        )
        print(f"SUMMARY {smoke.passed} passed, {smoke.failed} failed")
        return 1 if smoke.failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
