"""Safely reset only the reserved TriageOps demonstration organization."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import delete, or_, select

from scripts.seed_test_demo import (
    ANALYST_EMAIL_DEFAULT,
    DEMO_SLUG,
    OWNER_EMAIL_DEFAULT,
    seed,
)
from src.core.config import get_settings
from src.core.database import Base, SessionLocal
from src.models.sqlalchemy import IOCReportJob, Tenant
from src.services.audit_management_service import LocalAuditArtifactStorage


def reset(
    *,
    confirmed: bool,
    owner_password: str,
    analyst_password: str,
    owner_email: str = OWNER_EMAIL_DEFAULT,
    analyst_email: str = ANALYST_EMAIL_DEFAULT,
    session_factory=SessionLocal,
) -> dict:
    settings = get_settings()
    if settings.ENVIRONMENT.casefold() in {"production", "prod"}:
        raise RuntimeError("TriageOps demo reset is disabled in production")
    if not confirmed:
        raise RuntimeError("Reset not confirmed; pass --confirm-test-demo-reset")
    db = session_factory()
    removed = False
    try:
        tenant = db.query(Tenant).filter_by(slug=DEMO_SLUG).first()
        if tenant:
            tenant_id = tenant.id
            storage = LocalAuditArtifactStorage(settings.IOC_COMMERCIAL_ARTIFACT_DIRECTORY)
            for report in db.query(IOCReportJob).filter_by(tenant_id=tenant_id).all():
                if report.artifact_key:
                    try:
                        storage.delete(report.artifact_key)
                    except FileNotFoundError:
                        pass
            # Delete tenant-scoped rows in dependency order. No predicate is ever
            # broader than the reserved demo tenant identifier.
            # Some legacy join/detail tables do not carry tenant_id themselves.
            # Delete only rows whose foreign key points at a demo-tenant parent.
            for table in reversed(Base.metadata.sorted_tables):
                if table.name == "tenants" or "tenant_id" in table.c:
                    continue
                tenant_parent_conditions = []
                for foreign_key in table.foreign_keys:
                    parent = foreign_key.column.table
                    if "tenant_id" in parent.c:
                        tenant_parent_conditions.append(
                            foreign_key.parent.in_(
                                select(foreign_key.column).where(parent.c.tenant_id == tenant_id)
                            )
                        )
                if tenant_parent_conditions:
                    db.execute(delete(table).where(or_(*tenant_parent_conditions)))
            for table in reversed(Base.metadata.sorted_tables):
                if table.name == "tenants":
                    continue
                if "tenant_id" in table.c:
                    db.execute(delete(table).where(table.c.tenant_id == tenant_id))
            db.execute(delete(Tenant.__table__).where(Tenant.id == tenant_id, Tenant.slug == DEMO_SLUG))
            db.commit()
            removed = True
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
    result = seed(
        confirmed=True, owner_password=owner_password, analyst_password=analyst_password,
        owner_email=owner_email, analyst_email=analyst_email,
        session_factory=session_factory,
    )
    result["reset_removed_existing"] = removed
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm-test-demo-reset", action="store_true")
    args = parser.parse_args()
    result = reset(
        confirmed=args.confirm_test_demo_reset,
        owner_password=os.getenv("TEST_DEMO_OWNER_PASSWORD", ""),
        analyst_password=os.getenv("TEST_DEMO_ANALYST_PASSWORD", ""),
        owner_email=os.getenv("TEST_DEMO_OWNER_EMAIL", OWNER_EMAIL_DEFAULT),
        analyst_email=os.getenv("TEST_DEMO_ANALYST_EMAIL", ANALYST_EMAIL_DEFAULT),
    )
    print(f"TriageOps demo reset complete; recreated tenant {result['tenant_id']}")
    print(f"Removed prior demo tenant: {result['reset_removed_existing']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
