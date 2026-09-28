import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from api_client import VigilantAIAPIClient
from src.models.pydantic import IngestionBatchRequest


def test_collector_and_backend_use_the_same_canonical_batch():
    wire_payload = {
        "batch_id": "batch-1",
        "events": [{
            "source": "windows",
            "source_event_id": "42",
            "event_type": "process",
            "raw_event": {"EventID": 4688},
            "normalized_event": {"process": {"name": "powershell.exe"}},
            "severity": "medium",
            "timestamp": "2026-07-29T06:07:45.204461+00:00",
        }],
    }
    collector_payload = VigilantAIAPIClient._canonical_batch_payload(wire_payload)
    backend_payload = IngestionBatchRequest.model_validate(wire_payload).model_dump(
        mode="json", exclude_unset=True
    )
    compact = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"))
    assert compact(collector_payload) == compact(backend_payload)
