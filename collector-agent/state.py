import json
import os
from pathlib import Path
from typing import Any


class AtomicCheckpointStore:
    """Crash-safe local checkpoints with a last-known-good backup."""

    def __init__(self, path: str):
        self.path = Path(path)
        self.backup = self.path.with_suffix(self.path.suffix + ".bak")
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> dict[str, Any]:
        for candidate in (self.path, self.backup):
            try:
                if candidate.exists():
                    value = json.loads(candidate.read_text(encoding="utf-8"))
                    return value if isinstance(value, dict) else {}
            except (OSError, json.JSONDecodeError):
                continue
        return {}

    def save(self, value: dict[str, Any]) -> None:
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"), default=str)
            handle.flush()
            os.fsync(handle.fileno())
        if self.path.exists():
            os.replace(self.path, self.backup)
        os.replace(temporary, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
