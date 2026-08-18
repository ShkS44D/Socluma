from __future__ import annotations

import smtplib
from email.message import EmailMessage
from html import escape

from src.core.config import get_settings
from src.core.logging import logger


settings = get_settings()


class AuthEmailService:
    def __init__(self) -> None:
        self.captured: list[dict[str, str]] = []

    def _safe_header(self, value: str) -> str:
        if "\r" in value or "\n" in value:
            raise ValueError("Invalid email header")
        return value

    def send(self, *, recipient: str, subject: str, text: str, html: str) -> None:
        recipient = self._safe_header(recipient)
        subject = self._safe_header(subject)
        if settings.AUTH_EMAIL_CAPTURE:
            self.captured.append({"recipient": recipient, "subject": subject, "text": text, "html": html})
            return
        if not settings.SMTP_HOST:
            logger.info("Authentication email delivery skipped because SMTP is not configured")
            return
        message = EmailMessage()
        message["From"] = self._safe_header(settings.AUTH_EMAIL_FROM)
        message["To"] = recipient
        message["Subject"] = subject
        message.set_content(text)
        message.add_alternative(html, subtype="html")
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as client:
            if settings.SMTP_USE_TLS:
                client.starttls()
            if settings.SMTP_USERNAME:
                client.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD or "")
            client.send_message(message)

    def verification(self, recipient: str, link: str) -> None:
        safe = escape(link, quote=True)
        self.send(
            recipient=recipient,
            subject="Verify your TriageOps email",
            text=f"Verify your email: {link}",
            html=f"<p>Verify your TriageOps email:</p><p><a href=\"{safe}\">Verify email</a></p>",
        )

    def password_reset(self, recipient: str, link: str) -> None:
        safe = escape(link, quote=True)
        self.send(
            recipient=recipient,
            subject="Reset your TriageOps password",
            text=f"Reset your password: {link}",
            html=f"<p>A password reset was requested.</p><p><a href=\"{safe}\">Reset password</a></p>",
        )

    def security_notice(self, recipient: str, title: str, message: str) -> None:
        self.send(
            recipient=recipient,
            subject=self._safe_header(f"TriageOps security notice: {title}"),
            text=message,
            html=f"<p>{escape(message)}</p>",
        )


auth_email_service = AuthEmailService()
