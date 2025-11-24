"""Lightweight email utility used to emit verification messages."""
from __future__ import annotations

import logging
import uuid
from datetime import datetime
from pathlib import Path
from textwrap import dedent

from .config import Settings, get_settings

logger = logging.getLogger(__name__)


class EmailService:
    """Very small email helper that writes outbound mail to a local outbox."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.outbox_dir = Path(self.settings.email_outbox_dir) if self.settings.email_outbox_dir else None
        if self.outbox_dir:
            self.outbox_dir.mkdir(parents=True, exist_ok=True)
        self.last_message: dict[str, str] | None = None

    def send_verification_email(self, *, to_email: str, token: str) -> None:
        """Compose and persist a verification email containing the one-time token."""

        link = f"{self.settings.verification_base_url}?token={token}"
        subject = "Confirma tu cuenta"
        body = dedent(
            f"""
            Hola,

            Gracias por registrarte. Confirma tu correo copiando el siguiente enlace
            en tu navegador:

            {link}

            Si no solicitaste esta cuenta, puedes ignorar este mensaje.
            """
        ).strip()
        self._send(to_email=to_email, subject=subject, body=body)

    def _send(self, *, to_email: str, subject: str, body: str) -> None:
        message = f"From: {self.settings.email_from}\nTo: {to_email}\nSubject: {subject}\n\n{body}\n"
        logger.info("Email preparado para %s con asunto '%s'", to_email, subject)
        self.last_message = {"to": to_email, "subject": subject, "body": body}
        if not self.outbox_dir:
            return
        filename = self.outbox_dir / f"{datetime.now().strftime('%Y%m%dT%H%M%S%f')}_{uuid.uuid4().hex}.eml"
        filename.write_text(message, encoding="utf-8")
