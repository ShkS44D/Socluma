from __future__ import annotations

from typing import Any

import httpx

from src.connectors.base import ActionConnectorBase, ConnectorRequest, ConnectorResult


class HTTPConnectorMixin:
    def _request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        json_payload: dict[str, Any] | None = None,
        timeout_seconds: int = 30,
    ) -> ConnectorResult:
        with httpx.Client(timeout=timeout_seconds, follow_redirects=False) as client:
            response = client.request(method.upper(), url, headers=headers, json=json_payload)
        body = response.text[:5000]
        result = {
            "headers": {key: value for key, value in response.headers.items() if key.lower() not in {"authorization", "cookie"}},
            "body": body,
        }
        return ConnectorResult(
            success=200 <= response.status_code < 300,
            status_code=response.status_code,
            response=result,
            message=f"HTTP {response.status_code}",
        )


class WebhookConnector(HTTPConnectorMixin, ActionConnectorBase):
    connector_type = "webhook"
    display_name = "Webhook"

    def validate(self, config: dict[str, Any], credentials: dict[str, Any] | None = None) -> None:
        self._require(config, "url")

    def execute(self, request: ConnectorRequest) -> ConnectorResult:
        self.validate(request.config, request.credentials)
        headers = dict(request.config.get("headers") or {})
        if token := request.credentials.get("bearer_token"):
            headers["Authorization"] = f"Bearer {token}"
        payload = request.payload or {}
        return self._request(
            request.config.get("method", "POST"),
            request.config["url"],
            headers=headers,
            json_payload=payload,
            timeout_seconds=request.timeout_seconds,
        )

    def test_connection(self, config: dict[str, Any], credentials: dict[str, Any] | None = None) -> ConnectorResult:
        self.validate(config, credentials)
        return self._request(config.get("test_method", "POST"), config["url"], json_payload={"type": "triageops_test"}, timeout_seconds=10)

    def health(self, config: dict[str, Any], credentials: dict[str, Any] | None = None) -> ConnectorResult:
        self.validate(config, credentials)
        return ConnectorResult(success=True, message="Webhook connector configured")


class SlackConnector(WebhookConnector):
    connector_type = "slack"
    display_name = "Slack"

    def execute(self, request: ConnectorRequest) -> ConnectorResult:
        self.validate(request.config, request.credentials)
        webhook_url = request.credentials.get("webhook_url") or request.config.get("webhook_url")
        if not webhook_url:
            raise ValueError("Slack connector requires webhook_url in credentials or config")
        text = request.payload.get("text") or request.payload.get("message") or "TriageOps notification"
        blocks = request.payload.get("blocks")
        payload: dict[str, Any] = {"text": text}
        if blocks:
            payload["blocks"] = blocks
        return self._request("POST", webhook_url, json_payload=payload, timeout_seconds=request.timeout_seconds)

    def validate(self, config: dict[str, Any], credentials: dict[str, Any] | None = None) -> None:
        if credentials is None and not config.get("webhook_url"):
            return
        credentials = credentials or {}
        if not (credentials.get("webhook_url") or config.get("webhook_url")):
            raise ValueError("Slack connector requires webhook_url")


class TeamsConnector(WebhookConnector):
    connector_type = "teams"
    display_name = "Microsoft Teams"

    def execute(self, request: ConnectorRequest) -> ConnectorResult:
        self.validate(request.config, request.credentials)
        webhook_url = request.credentials.get("webhook_url") or request.config.get("webhook_url")
        title = request.payload.get("title") or "TriageOps notification"
        text = request.payload.get("text") or request.payload.get("message") or title
        payload = {"@type": "MessageCard", "@context": "https://schema.org/extensions", "summary": title, "title": title, "text": text}
        return self._request("POST", webhook_url, json_payload=payload, timeout_seconds=request.timeout_seconds)

    def validate(self, config: dict[str, Any], credentials: dict[str, Any] | None = None) -> None:
        if credentials is None and not config.get("webhook_url"):
            return
        credentials = credentials or {}
        if not (credentials.get("webhook_url") or config.get("webhook_url")):
            raise ValueError("Teams connector requires webhook_url")


class GenericRESTConnector(HTTPConnectorMixin, ActionConnectorBase):
    connector_type = "generic_rest"
    display_name = "Generic REST API"

    def validate(self, config: dict[str, Any], credentials: dict[str, Any] | None = None) -> None:
        self._require(config, "base_url")

    def execute(self, request: ConnectorRequest) -> ConnectorResult:
        self.validate(request.config, request.credentials)
        endpoint = request.payload.get("endpoint") or request.config.get("endpoint") or "/"
        url = request.config["base_url"].rstrip("/") + "/" + str(endpoint).lstrip("/")
        headers = dict(request.config.get("headers") or {})
        credentials = request.credentials or {}
        if api_key := credentials.get("api_key"):
            header_name = credentials.get("api_key_header", "Authorization")
            headers[header_name] = credentials.get("api_key_prefix", "Bearer ") + api_key
        return self._request(
            request.payload.get("method") or request.config.get("method", "POST"),
            url,
            headers=headers,
            json_payload=request.payload.get("json") or request.payload.get("body") or {},
            timeout_seconds=request.timeout_seconds,
        )

    def test_connection(self, config: dict[str, Any], credentials: dict[str, Any] | None = None) -> ConnectorResult:
        self.validate(config, credentials)
        path = config.get("health_path") or "/"
        return self._request("GET", config["base_url"].rstrip("/") + "/" + path.lstrip("/"), timeout_seconds=10)

    def health(self, config: dict[str, Any], credentials: dict[str, Any] | None = None) -> ConnectorResult:
        return self.test_connection(config, credentials)
