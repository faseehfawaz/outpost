"""
Extract exfil indicators from PHP source text using static string analysis.
"""

import re

from pkintel.models import Indicator, IndicatorType
from pkintel.redact import redact, sha256_hex

# Indicator patterns
TELEGRAM_BOT_TOKEN_RE = re.compile(r"(\d{8,10}:[A-Za-z0-9_-]{35})")
TELEGRAM_CHAT_ID_RE = re.compile(r'(?i)(?:chat_id|chatid)\s*=>?\s*[\'"]?([-\d]+)[\'"]?')
DISCORD_WEBHOOK_RE = re.compile(r"(https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+)")
EMAIL_RE = re.compile(r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})")
URL_RE = re.compile(r'(https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s\'"]*)?)')


def extract_indicators(text: str, file_path: str) -> list[Indicator]:
    """Extract indicators from PHP source text without executing it."""
    indicators = []

    def _add_indicator(ind_type, value, conf=1.0):
        val_hash = sha256_hex(value.encode("utf-8"))
        # Ensure uniqueness per file in this run
        if not any(i.type == ind_type and i.value_hash == val_hash for i in indicators):
            indicators.append(
                Indicator(
                    type=ind_type,
                    value_hash=val_hash,
                    redacted_display=redact(value),
                    full_value_encrypted=b"",  # Set by DB layer if needed
                    confidence=conf,
                    found_in_path=file_path,
                    meta={},
                )
            )

    for match in TELEGRAM_BOT_TOKEN_RE.finditer(text):
        _add_indicator(IndicatorType.TELEGRAM_BOT, match.group(1), 1.0)

    for match in TELEGRAM_CHAT_ID_RE.finditer(text):
        _add_indicator(IndicatorType.TELEGRAM_CHAT, match.group(1), 0.9)

    for match in DISCORD_WEBHOOK_RE.finditer(text):
        _add_indicator(IndicatorType.DISCORD_WEBHOOK, match.group(1), 1.0)

    # Only consider emails in specific contexts to reduce noise
    if "mail(" in text or "$to" in text.lower():
        for match in EMAIL_RE.finditer(text):
            _add_indicator(IndicatorType.EMAIL, match.group(1), 0.8)

    # URLs often found in exfil functions
    if any(func in text for func in ["file_get_contents", "curl_setopt", "fopen"]):
        for match in URL_RE.finditer(text):
            url = match.group(1)
            # Skip localhost or common internal/benign looking urls
            if "localhost" not in url and "127.0.0.1" not in url:
                _add_indicator(IndicatorType.URL, url, 0.7)

    return indicators
