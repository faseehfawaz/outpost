"""Brand detection and phishing-keyword density over a fetched page.

We decide *whom* a page impersonates by matching brand keywords/patterns against
the page title, its visible text, and the URL. UAE-priority brands (passed in
from ``settings.priority_brands``) are checked first so a local target always
wins over a generic global one. All matching is plain regex — no execution.
"""

from __future__ import annotations

import re

from bs4 import BeautifulSoup

# Generic global phishing targets -> case-insensitive regex alternatives.
# Checked only after the caller's priority (UAE) brands.
GENERIC_BRAND_PATTERNS: dict[str, list[str]] = {
    "Microsoft": [
        r"microsoft",
        r"office\W{0,3}365",
        r"\bo365\b",
        r"outlook",
        r"onedrive",
        r"sharepoint",
    ],
    "Apple": [r"\bapple\b", r"icloud", r"apple\W{0,3}id"],
    "PayPal": [r"paypal"],
    "Google": [r"\bgoogle\b", r"gmail"],
    "Amazon": [r"\bamazon\b", r"\baws\b"],
    "DHL": [r"\bdhl\b"],
    "FedEx": [r"fedex"],
    "Netflix": [r"netflix"],
    "Meta": [r"facebook", r"instagram", r"\bmeta\b"],
    "LinkedIn": [r"linkedin"],
    "Coinbase": [r"coinbase"],
    "Binance": [r"binance"],
}

# Phrases whose presence raises suspicion. Density (count of distinct hits) feeds
# the score; individually weak, collectively meaningful.
PHISH_KEYWORDS: list[str] = [
    "verify your account",
    "verify your identity",
    "confirm your identity",
    "confirm your password",
    "update your account",
    "update your information",
    "unusual activity",
    "suspicious activity",
    "account suspended",
    "account locked",
    "account has been limited",
    "reactivate",
    "revalidate",
    "sign in",
    "log in",
    "login",
    "secure login",
    "online banking",
    "internet banking",
    "net banking",
    "one-time password",
    "otp code",
    "card number",
    "expiry date",
    "security code",
    "pin code",
    "session expired",
    "click here to verify",
    "confirm now",
]


def extract_text(html: str | None) -> tuple[str, str]:
    """Return ``(title, visible_text)`` extracted from ``html``.

    Script/style/noscript/template content is stripped so keyword matching sees
    only human-visible text.
    """
    if not html:
        return "", ""
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:  # pragma: no cover - defensive against malformed markup
        return "", ""
    for tag in soup(["script", "style", "noscript", "template"]):
        tag.extract()
    title = ""
    if soup.title and soup.title.string:
        title = soup.title.string.strip()
    text = soup.get_text(" ", strip=True)
    return title, text


def _name_to_pattern(name: str) -> str:
    """Turn a brand display name into a tolerant, word-bounded regex.

    ``"Emirates NBD"`` -> ``\\bemirates\\W{0,3}nbd\\b`` — matches the spaced form,
    a squashed ``emiratesnbd``, and hyphen/underscore separated variants, while
    ``\\b`` keeps short names like ``du`` from matching inside other words.
    """
    tokens = [re.escape(t) for t in name.split() if t]
    if not tokens:
        return r"(?!x)x"  # never matches
    return r"\b" + r"\W{0,3}".join(tokens) + r"\b"


def _where(pattern: str, title: str, url: str) -> str:
    if re.search(pattern, title, re.IGNORECASE):
        return "title"
    if re.search(pattern, url, re.IGNORECASE):
        return "url"
    return "body"


def detect_brand(
    html: str | None,
    url: str,
    priority_brands: list[str],
) -> tuple[str | None, list[str]]:
    """Detect the impersonated brand.

    Returns ``(brand_or_None, reasons)``. ``priority_brands`` (UAE-first) are
    matched before the generic global set, and the first match wins — so list
    more specific names (``"Emirates NBD"``) before broader ones (``"Emirates"``).
    """
    title, text = extract_text(html)
    url_l = (url or "").lower()
    haystack = " ".join([title, text, url_l]).lower()
    reasons: list[str] = []

    for brand in priority_brands or []:
        pattern = _name_to_pattern(brand)
        if re.search(pattern, haystack, re.IGNORECASE):
            reasons.append(f"priority_brand:{brand} in {_where(pattern, title, url_l)}")
            return brand, reasons

    for brand, patterns in GENERIC_BRAND_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, haystack, re.IGNORECASE):
                reasons.append(f"brand:{brand} in {_where(pattern, title, url_l)}")
                return brand, reasons

    return None, reasons


def keyword_hits(html: str | None, url: str) -> tuple[int, list[str]]:
    """Count distinct phishing keywords/phrases seen in visible text + URL.

    Returns ``(count, matched_keywords)``.
    """
    _, text = extract_text(html)
    haystack = (text + " " + (url or "")).lower()
    hits = [kw for kw in PHISH_KEYWORDS if kw in haystack]
    return len(hits), hits
