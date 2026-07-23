"""Redaction & hashing helpers.

The single source of truth for how a raw indicator becomes something safe to
publish. Ethics non-negotiable: full exfil values (Telegram tokens, webhooks,
SMTP creds, dropbox emails) are NEVER surfaced publicly. We publish a hash and a
partial display; the full value goes only to an abuse desk, encrypted at rest.
"""

from __future__ import annotations

import hashlib
import re


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8", "surrogatepass")
    return hashlib.sha256(data).hexdigest()


def _mask(s: str, keep_start: int = 4, keep_end: int = 0) -> str:
    if len(s) <= keep_start + keep_end:
        return "*" * len(s)
    end = s[-keep_end:] if keep_end else ""
    return f"{s[:keep_start]}{'*' * 3}{end}"


def redact_telegram_token(token: str) -> str:
    # 12345678:AAF-xxxx...  ->  12345***:AAF***
    if ":" in token:
        bot_id, secret = token.split(":", 1)
        return f"{_mask(bot_id)}:{_mask(secret)}"
    return _mask(token)


def redact_email(email: str) -> str:
    # attacker@gmail.com -> att***@gmail.com  (attacker's own dropbox, not a victim)
    if "@" in email:
        local, domain = email.split("@", 1)
        return f"{_mask(local, keep_start=2)}@{domain}"
    return _mask(email)


def redact_url(url: str) -> str:
    # keep scheme+host, mask the path/token that follows
    m = re.match(r"^(https?://[^/]+)(/.*)?$", url)
    if not m:
        return _mask(url, keep_start=8)
    host = m.group(1)
    return f"{host}/***" if m.group(2) else host


def redact_discord_webhook(url: str) -> str:
    m = re.match(r"^(https://discord(?:app)?\.com/api/webhooks/\d+)/", url)
    return f"{m.group(1)}/***" if m else redact_url(url)


def redact_generic(value: str) -> str:
    return _mask(value, keep_start=4, keep_end=2)


def redact(indicator_type: str, value: str) -> str:
    """Dispatch to the right redactor for an indicator type."""
    return {
        "telegram_token": redact_telegram_token,
        "telegram_chat": lambda v: _mask(v, keep_start=3),
        "discord_webhook": redact_discord_webhook,
        "email": redact_email,
        "smtp": redact_generic,
        "url": redact_url,
    }.get(indicator_type, redact_generic)(value)
