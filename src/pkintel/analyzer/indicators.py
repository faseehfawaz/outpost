"""
Extract exfil indicators from PHP source text using static string analysis.
"""

import re

from pkintel.models import Indicator, IndicatorType
from pkintel.redact import redact, sha256_hex

# Indicator patterns
TELEGRAM_BOT_TOKEN_RE = re.compile(r"\b(\d{8,12}:[A-Za-z0-9_-]{30,50})\b")
TELEGRAM_CHAT_ID_RE = re.compile(r'(?i)(?:chat_id|chatid)\s*=>?\s*[\'"]?([-\d]+)[\'"]?')
DISCORD_WEBHOOK_RE = re.compile(r"(https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+)")
SLACK_WEBHOOK_RE = re.compile(
    r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)"
)
TEAMS_WEBHOOK_RE = re.compile(r"(https://[a-z0-9-]+\.webhook\.office\.com/webhookb2/[^\s'\"]+)")
SENDGRID_KEY_RE = re.compile(r"\b(SG\.[A-Za-z0-9_-]{20,80})\b")
RESEND_KEY_RE = re.compile(r"\b(re_[A-Za-z0-9]{20,60})\b")
FIREBASE_RE = re.compile(r"(https://[a-z0-9-]+\.firebaseio\.com[^\s'\"]*)")
SUPABASE_RE = re.compile(r"(https://[a-z]+\.supabase\.co/rest/v1/[^\s'\"]+)")
EMAIL_RE = re.compile(r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})")
URL_RE = re.compile(r'(https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s\'"]*)?)')


def extract_indicators(text: str, file_path: str) -> list[Indicator]:
    """Extract indicators from PHP source text without executing it."""
    indicators = []

    seen: set[tuple[str, str]] = set()

    def _add_indicator(ind_type, value, conf=1.0):
        val_hash = sha256_hex(value.encode("utf-8"))
        # Ensure uniqueness per file in this run
        if (ind_type.value, val_hash) not in seen:
            seen.add((ind_type.value, val_hash))
            indicators.append(
                Indicator(
                    type=ind_type,
                    value_hash=val_hash,
                    redacted_display=redact(ind_type.value, value),
                    # Carry the full value in-process ONLY. The model marks this
                    # repr=False so it never lands in a log line or traceback.
                    # pkintel.analyzer.runner encrypts it (pkintel.crypto) before
                    # it touches the DB, and it is never returned by the API.
                    #
                    # Was: full_value_encrypted=b"" — not a field on Indicator, so
                    # Pydantic silently dropped it and full_value stayed None,
                    # leaving indicators.full_value_encrypted empty for every kit
                    # ever analyzed. The abuse-desk evidence path was dead.
                    full_value=value,
                    confidence=conf,
                    found_in_path=file_path,
                    meta={},
                )
            )

    for match in TELEGRAM_BOT_TOKEN_RE.finditer(text):
        _add_indicator(IndicatorType.telegram_token, match.group(1), 1.0)

    for match in TELEGRAM_CHAT_ID_RE.finditer(text):
        _add_indicator(IndicatorType.telegram_chat, match.group(1), 0.9)

    for match in DISCORD_WEBHOOK_RE.finditer(text):
        _add_indicator(IndicatorType.discord_webhook, match.group(1), 1.0)

    for match in SLACK_WEBHOOK_RE.finditer(text):
        _add_indicator(IndicatorType.slack_webhook, match.group(1), 1.0)

    for match in TEAMS_WEBHOOK_RE.finditer(text):
        _add_indicator(IndicatorType.teams_webhook, match.group(1), 1.0)

    for match in SENDGRID_KEY_RE.finditer(text):
        _add_indicator(IndicatorType.sendgrid_key, match.group(1), 1.0)

    for match in RESEND_KEY_RE.finditer(text):
        _add_indicator(IndicatorType.resend_key, match.group(1), 1.0)

    for match in FIREBASE_RE.finditer(text):
        _add_indicator(IndicatorType.firebase, match.group(1), 1.0)

    for match in SUPABASE_RE.finditer(text):
        _add_indicator(IndicatorType.supabase, match.group(1), 1.0)

    # Only consider emails in specific contexts to reduce noise
    if "mail(" in text or "$to" in text.lower():
        for match in EMAIL_RE.finditer(text):
            _add_indicator(IndicatorType.email, match.group(1), 0.8)

    # URLs often found in exfil functions
    if any(func in text for func in ["file_get_contents", "curl_setopt", "fopen"]):
        for match in URL_RE.finditer(text):
            url = match.group(1)
            # Skip localhost or common internal/benign looking urls
            if "localhost" not in url and "127.0.0.1" not in url:
                _add_indicator(IndicatorType.url, url, 0.7)

    return indicators
