from __future__ import annotations

from src.connectors.base import ActionConnectorBase
from src.connectors.email_connector import SMTPEmailConnector
from src.connectors.http_connectors import GenericRESTConnector, SlackConnector, TeamsConnector, WebhookConnector


class ConnectorRegistry:
    def __init__(self) -> None:
        self._connectors: dict[str, ActionConnectorBase] = {}

    def register(self, connector: ActionConnectorBase) -> None:
        self._connectors[connector.connector_type] = connector

    def get(self, connector_type: str) -> ActionConnectorBase:
        if connector_type not in self._connectors:
            raise ValueError(f"Unsupported connector type: {connector_type}")
        return self._connectors[connector_type]

    def list_types(self) -> list[dict[str, str]]:
        return [
            {"type": connector.connector_type, "name": connector.display_name}
            for connector in sorted(self._connectors.values(), key=lambda item: item.display_name)
        ]


connector_registry = ConnectorRegistry()
connector_registry.register(WebhookConnector())
connector_registry.register(SlackConnector())
connector_registry.register(TeamsConnector())
connector_registry.register(SMTPEmailConnector())
connector_registry.register(GenericRESTConnector())
