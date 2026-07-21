import os
import tempfile

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.core.database import Base
from src.models.sqlalchemy import MitreTechnique
from src.services.default_detection_rules import DEFAULT_DETECTION_RULES
from src.services.mitre_technique_service import mitre_technique_service


def test_offline_authoritative_catalog_is_complete_idempotent_and_structured(monkeypatch):
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    engine = create_engine(f"sqlite:///{path}")
    Session = sessionmaker(bind=engine)
    Base.metadata.create_all(engine)
    db = None
    try:
        monkeypatch.setattr("socket.create_connection", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("network forbidden")))
        db = Session()
        first = mitre_technique_service.bootstrap_catalog(db)
        second = mitre_technique_service.bootstrap_catalog(db)
        required = {item["mitre_technique_id"] for item in DEFAULT_DETECTION_RULES if item.get("enabled", True)}
        resolved = {row.technique_id for row in db.query(MitreTechnique).filter(MitreTechnique.technique_id.in_(required)).all()}
        assert resolved == required
        assert mitre_technique_service.load_catalog()["source_sha256"] == "f857d8f78f2f0c0b7db321a711a39fba98546c1e3076a657684850c83d0962fb"
        assert first["created"] == first["total"]
        assert second == {"created": 0, "updated": first["total"], "total": first["total"]}
        powershell = db.query(MitreTechnique).filter_by(technique_id="T1059.001").one()
        assert powershell.parent_technique_id == "T1059"
        assert powershell.parent_technique_name == "Command and Scripting Interpreter"
        assert powershell.sub_technique_id == "T1059.001"
        assert powershell.sub_technique_name == "PowerShell"
        assert powershell.tactic.value == "Execution"
        assert powershell.tactic_id == "TA0002"
        scheduled = db.query(MitreTechnique).filter_by(technique_id="T1053.005").one()
        assert [item["name"] for item in scheduled.tactics] == ["Execution", "Persistence", "Privilege Escalation"]
        assert mitre_technique_service.resolve(db, "T9999") is None
        db.close()
    finally:
        if db is not None:
            db.close()
        engine.dispose()
        try:
            os.remove(path)
        except PermissionError:
            pass
