"""Add the controlled Socluma demonstration story to an existing Default Tenant."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.seed_test_demo import OWNER_EMAIL_DEFAULT, seed


DEFAULT_TENANT_SLUG = "default"
DEFAULT_ANALYST_EMAIL = "default.analyst@example.com"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm-default-tenant-demo-seed", action="store_true")
    args = parser.parse_args()
    if not args.confirm_default_tenant_demo_seed:
        raise RuntimeError(
            "Default Tenant seed not confirmed; pass --confirm-default-tenant-demo-seed"
        )
    result = seed(
        confirmed=True,
        owner_password=os.getenv("DEFAULT_DEMO_OWNER_PASSWORD", ""),
        analyst_password=os.getenv("DEFAULT_DEMO_ANALYST_PASSWORD", ""),
        owner_email=os.getenv("DEFAULT_DEMO_OWNER_EMAIL", OWNER_EMAIL_DEFAULT),
        analyst_email=os.getenv("DEFAULT_DEMO_ANALYST_EMAIL", DEFAULT_ANALYST_EMAIL),
        target_tenant_slug=DEFAULT_TENANT_SLUG,
        allow_existing_tenant=True,
    )
    print(f"Default Tenant demo seed complete for tenant {result['tenant_id']}")
    print(f"Owner account: {result['owner_email']} (existing password preserved)")
    print(f"Analyst account: {result['analyst_email']} (password supplied through environment)")
    print(f"Incident: {result['incident_id']} | Report: {result['report_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
