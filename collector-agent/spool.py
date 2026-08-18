import base64
import json
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken


class DurableEventSpool:
    """Bounded FIFO SQLite spool. Payload blobs are encrypted at rest."""

    def __init__(self, path: str, max_bytes: int = 268_435_456):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes
        self.key_path = self.path.with_suffix(".key")
        self.cipher = Fernet(self._load_or_create_key())
        self._lock = threading.RLock()
        self.db = sqlite3.connect(str(self.path), timeout=10, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, created REAL NOT NULL, payload BLOB NOT NULL, size INTEGER NOT NULL)")
        self.db.commit()
        for target in (self.path, self.key_path):
            try:
                os.chmod(target, 0o600)
            except OSError:
                pass

    def _load_or_create_key(self) -> bytes:
        if self.key_path.exists():
            return self.key_path.read_bytes().strip()
        key = Fernet.generate_key()
        temporary = self.key_path.with_suffix(".tmp")
        temporary.write_bytes(key)
        os.replace(temporary, self.key_path)
        return key

    def append(self, event: dict[str, Any]) -> str:
        event_id = str(uuid.uuid4())
        plaintext = json.dumps(event, sort_keys=True, separators=(",", ":"), default=str).encode()
        encrypted = self.cipher.encrypt(plaintext)
        with self._lock:
            self.db.execute("INSERT INTO events(id, created, payload, size) VALUES (?, ?, ?, ?)", (event_id, time.time(), encrypted, len(encrypted)))
            self.db.commit()
            self._trim()
        return event_id

    def peek(self, limit: int) -> list[tuple[str, dict[str, Any]]]:
        with self._lock:
            rows = self.db.execute("SELECT id, payload FROM events ORDER BY created, id LIMIT ?", (limit,)).fetchall()
        result = []
        corrupt = []
        for event_id, payload in rows:
            try:
                result.append((event_id, json.loads(self.cipher.decrypt(payload))))
            except (InvalidToken, json.JSONDecodeError, TypeError):
                corrupt.append(event_id)
        if corrupt:
            self.ack(corrupt)
        return result

    def ack(self, event_ids: list[str]) -> None:
        if not event_ids:
            return
        with self._lock:
            self.db.executemany("DELETE FROM events WHERE id = ?", [(value,) for value in event_ids])
            self.db.commit()

    def stats(self) -> dict[str, int]:
        with self._lock:
            count, size = self.db.execute("SELECT count(*), coalesce(sum(size), 0) FROM events").fetchone()
        return {"queue_depth": int(count), "spool_size_bytes": int(size)}

    def _trim(self) -> None:
        while self.stats()["spool_size_bytes"] > self.max_bytes:
            row = self.db.execute("SELECT id FROM events ORDER BY created, id LIMIT 1").fetchone()
            if not row:
                break
            self.ack([row[0]])

    def close(self) -> None:
        with self._lock:
            self.db.close()
