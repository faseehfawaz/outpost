"""SMTP Email Dispatcher for Abuse Reports and Takedown Notices.

Handles sending rendered plaintext takedown reports via SMTP (TLS/SSL supported).
Supports an optional ``takedown_override_recipient`` to redirect all outbound
takedowns to a test inbox (e.g., faseehcodes@gmail.com) during validation.
"""

from __future__ import annotations

import smtplib
from email.message import EmailMessage

from pkintel.config import settings
from pkintel.logging import get_logger

log = get_logger(__name__)


def send_takedown_email(to_address: str, subject: str, body: str) -> str:
    """Send a takedown email via SMTP.

    Returns the actual recipient address used (which may be overridden by
    ``takedown_override_recipient`` if configured for testing).
    """
    recipient = settings.takedown_override_recipient.strip() or to_address.strip()

    if not settings.smtp_host:
        log.warning("smtp_not_configured", recipient=recipient)
        raise RuntimeError(
            "SMTP settings not configured. Please set PKINTEL_SMTP_HOST, "
            "PKINTEL_SMTP_USER, and PKINTEL_SMTP_PASS in your environment."
        )

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.takedown_from_email
    msg["To"] = recipient
    msg.set_content(body)

    log.info("sending_email", to=recipient, host=settings.smtp_host, port=settings.smtp_port)

    if settings.smtp_port == 465:
        # SSL
        with smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=15) as server:
            if settings.smtp_user and settings.smtp_pass:
                server.login(settings.smtp_user, settings.smtp_pass)
            server.send_message(msg)
    else:
        # TLS / StartTLS (587 / 25)
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as server:
            if settings.smtp_use_tls:
                server.starttls()
            if settings.smtp_user and settings.smtp_pass:
                server.login(settings.smtp_user, settings.smtp_pass)
            server.send_message(msg)

    log.info("email_sent_successfully", recipient=recipient)
    return recipient
