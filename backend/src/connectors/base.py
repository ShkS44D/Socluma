from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


class ConnectorValidationError(ValueError):
    pass


@dataclass
class ConnectorRequest:
    action: str
    payload: dict[str, Any]
    config: dict[str, Any]
    credentials: dict[str, Any] = field(default_factory=dict)
    timeout_seconds: int = 30
    correlation_id: str | None = None


@dataclass
class ConnectorResult:
    success: bool
    status_code: int | None = None
    response: dict[str, Any] = field(default_factory=dict)
    message: str | None = None
    rollback_supported: bool = False


class ActionConnectorBase(ABC):
    connector_type: str
    display_name: str

    @abstractmethod
    def validate(self, config: dict[str, Any], credentials: dict[str, Any] | None = None) -> None:
        """Validate connector configuration and optional credential material."""

    @abstractmethod
    def execute(self, request: ConnectorRequest) -> ConnectorResult:
        """Execute the connector action."""

    @abstractmethod
    def test_connection(self, config: dict[str, Any], credentials: dict[str, Any] | None = None) -> ConnectorResult:
        """Verify the remote endpoint accepts a minimal request."""

    @abstractmethod
    def health(self, config: dict[str, Any], credentials: dict[str, Any] | None = None) -> ConnectorResult:
        """Return a lightweight connector health result."""

    def rollback(self, request: ConnectorRequest, previous_result: ConnectorResult) -> ConnectorResult:
        return ConnectorResult(
            success=False,
            message=f"Rollback is not supported for {self.display_name}",
            response={"rollback_supported": False},
        )

    def _require(self, data: dict[str, Any], key: str) -> Any:
        value = data.get(key)
        if value in (None, ""):
            raise ConnectorValidationError(f"Missing required field: {key}")
        return value
