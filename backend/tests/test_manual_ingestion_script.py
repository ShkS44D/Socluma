import runpy
from pathlib import Path


def test_manual_ingestion_script_is_side_effect_free_when_collected(monkeypatch):
    def unexpected_request(*args, **kwargs):
        raise AssertionError("manual ingestion script made a request during collection")

    monkeypatch.setattr("requests.sessions.Session.request", unexpected_request)
    script = Path(__file__).resolve().parents[1] / "test_event_ingestion.py"

    namespace = runpy.run_path(str(script), run_name="pytest_collection")

    assert callable(namespace["main"])
    assert "json.dumps" not in script.read_text(encoding="utf-8")
