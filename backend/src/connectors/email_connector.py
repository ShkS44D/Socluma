from __future__ import annotations

import smtplib
from email.message import EmailMessage
from typing import Any

from src.connectors.base import ActionConnectorBase, ConnectorRequest, ConnectorResult


class SMTPEmailConnector(ActionConnectorBase):
    connector_type = "smtp_email"
    display_name = "SMTP Email"

    def validate(self, config: dict[str, Any], credentials: dict[str, Any] | None = None) -> None:
        self._require(config, "host")
        self._require(config, "from_address")
        if int(config.get("port", 587)) <= 0:
            raise ValueError("SMTP port must be positive")

    def execute(self, request: ConnectorRequest) -> ConnectorResult:
        self.validate(request.config, request.credentials)
        payload = request.payload or {}
        recipients = payload.get("to") or request.config.get("to")
        if isinstance(recipients, str):
            recipients = [recipients]
        if not recipients:
            raise ValueError("SMTP email action requires at least one recipient")

        message = EmailMessage()
        message["From"] = request.config["from_address"]
        message["To"] = ", ".join(recipients)
        message["Subject"] = payload.get("subject") or "VigilantAI notification"
        message.set_content(payload.get("body") or payload.get("message") or "")

        port = int(request.config.get("port", 587))
        use_tls = bool(request.config.get("use_tls", True))
        username = request.credentials.get("username")
        password = request.credentials.get("password")

        with smtplib.SMTP(request.config["host"], port, timeout=request.timeout_seconds) as smtp:
            if use_tls:
                smtp.starttls()
            if username and password:
                smtp.login(username, password)
            smtp.send_message(message)

        return ConnectorResult(success=True, message="Email sent", response={"recipients": recipients})

    def test_connection(self, config: dict[str, Any], credentials: dict[str, Any] | None = None) -> ConnectorResult:
        self.validate(config, credentials)
        port = int(config.get("port", 587))
        with smtplib.SMTP(config["host"], port, timeout=10) as smtp:
            code, message = smtp.noop()
        return ConnectorResult(success=200 <= code < 400, status_code=code, message=message.decode("utf-8", "ignore"))

    def health(self, config: dict[str, Any], credentials: dict[str, Any] | None = None) -> ConnectorResult:
        return self.test_connection(config, credentials)
