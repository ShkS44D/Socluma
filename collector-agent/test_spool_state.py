from pathlib import Path
import threading

from spool import DurableEventSpool
from state import AtomicCheckpointStore


def test_encrypted_spool_fifo_and_ack(tmp_path: Path):
    spool = DurableEventSpool(str(tmp_path / "spool.db"), max_bytes=1_000_000)
    first = spool.append({"source": "one", "raw_event": {"secret": "value"}})
    second = spool.append({"source": "two", "raw_event": {}})
    assert [item[1]["source"] for item in spool.peek(10)] == ["one", "two"]
    assert b'"secret":"value"' not in (tmp_path / "spool.db").read_bytes()
    spool.ack([first])
    assert [item[0] for item in spool.peek(10)] == [second]
    spool.close()


def test_checkpoint_recovers_from_corrupt_primary(tmp_path: Path):
    store = AtomicCheckpointStore(str(tmp_path / "checkpoint.json"))
    store.save({"offset": 1})
    store.save({"offset": 2})
    (tmp_path / "checkpoint.json").write_text("{broken", encoding="utf-8")
    assert store.load() == {"offset": 1}


def test_spool_stats_are_safe_from_heartbeat_thread(tmp_path: Path):
    spool = DurableEventSpool(str(tmp_path / "threaded.db"))
    spool.append({"event": "thread-safe"})
    results = []
    thread = threading.Thread(target=lambda: results.append(spool.stats()))
    thread.start()
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert results and results[0]["queue_depth"] == 1
    spool.close()
