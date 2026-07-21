"""Idempotently synchronize the pinned offline MITRE ATT&CK Enterprise catalog."""

import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from src.core.database import SessionLocal
from src.services.mitre_technique_service import mitre_technique_service


def main() -> None:
    db = SessionLocal()
    try:
        result = mitre_technique_service.bootstrap_catalog(db)
        print(f"MITRE catalog synchronized: {result['total']} total, {result['created']} created, {result['updated']} updated.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
