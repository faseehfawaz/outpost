"""Login-form analysis — the single strongest phishing signal.

A password input whose enclosing ``<form>`` posts to a *different registrable
domain* than the page it lives on is the classic credential-harvesting tell: a
legitimate login posts back to its own site, a kit ships credentials off to the
attacker's collector. We compute that here with BeautifulSoup only — no
execution, no network.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

# A tiny allowance for common multi-label public suffixes so that, e.g.,
# ``example.co.uk`` is treated as one registrable domain rather than ``co.uk``.
# This is deliberately not the full Public Suffix List — triage only needs a
# good-enough same-site vs off-site decision, not registrar-grade accuracy.
_TWO_LEVEL_SLDS = {"co", "com", "org", "net", "gov", "edu", "ac"}


@dataclass
class FormSignal:
    """Outcome of scanning a page's forms."""

    has_password_field: bool = False
    posts_offdomain: bool = False
    action_hosts: list[str] = field(default_factory=list)
    suspicious: bool = False


def registrable_domain(host: str) -> str:
    """Best-effort eTLD+1 for ``host`` (no Public Suffix List dependency).

    Returns the last two labels, or three when the second-to-last looks like a
    two-level SLD (``co.uk``, ``com.au`` ...). Strips any port and trailing dot.
    """
    host = (host or "").strip().lower().rstrip(".")
    if ":" in host:
        host = host.split(":", 1)[0]
    if not host:
        return ""
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if labels[-2] in _TWO_LEVEL_SLDS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _form_has_password(form) -> bool:
    for inp in form.find_all("input"):
        if (inp.get("type") or "").strip().lower() == "password":
            return True
    return False


def analyze_forms(html: str | None, page_url: str) -> FormSignal:
    """Scan every ``<form>`` in ``html`` and summarise the credential signal.

    ``suspicious`` is True iff some form contains a password field *and* posts to
    a different registrable domain than ``page_url``.
    """
    signal = FormSignal()
    if not html:
        return signal
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:  # pragma: no cover - defensive against malformed markup
        return signal

    page_domain = registrable_domain(urlsplit(page_url).netloc)
    action_hosts: list[str] = []
    has_password = False
    posts_off = False

    for form in soup.find_all("form"):
        form_pw = _form_has_password(form)
        if form_pw:
            has_password = True

        action = (form.get("action") or "").strip()
        # Empty/relative action resolves against the page itself (same domain).
        resolved = urljoin(page_url, action) if action else page_url
        action_host = urlsplit(resolved).netloc
        if action_host:
            action_hosts.append(action_host)
            action_domain = registrable_domain(action_host)
            if form_pw and action_domain and page_domain and action_domain != page_domain:
                posts_off = True

    signal.has_password_field = has_password
    signal.posts_offdomain = posts_off
    signal.action_hosts = sorted(set(action_hosts))
    signal.suspicious = has_password and posts_off
    return signal
