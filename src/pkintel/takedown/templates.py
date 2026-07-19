"""Pure abuse-report builders.

Each function returns a ``(subject, body)`` tuple and performs **no I/O**, so the
suite can assert on their exact wording without a database or network.

Ethics baked into the wording (``docs/SCOPE_AND_ETHICS.md``):

* Bodies cite only **REDACTED** indicator values (``redacted_display``). Full
  exfil values are never placed in a body that could be logged or forwarded; a
  standing note tells the abuse desk that full values are available through their
  own secure channel.
* The Telegram report explicitly states that we have not and will not interact
  with the bot — we are reporting the token, never using it (non-negotiable #2).
* Every report describes the finding as passive research (non-negotiable #5).
"""

from __future__ import annotations

from typing import Any

from pkintel.config import settings

# Standing abuse-desk contacts (who we report *to* — never attacker channels).
TELEGRAM_ABUSE_CONTACT = "abuse@telegram.org"
APWG_CONTACT = "reports@apwg.org"
GSB_CONTACT = "Google Safe Browsing"  # submitted via the Safe Browsing API
AECERT_CONTACT = "aeCERT (TDRA)"  # UAE CERT — victim-data escalation path

_PASSIVE_NOTE = (
    "This finding was produced by passive, rate-limited research: we only "
    "retrieved content the server already served to any anonymous visitor. We "
    "did not authenticate, guess or enumerate paths, brute-force anything, or "
    "interact with any attacker-controlled channel."
)

_REDACTION_NOTE = (
    "Indicator values shown above are REDACTED for safe handling. The full "
    "values are available to your abuse desk on request through your own secure "
    "channel — we do not publish or email live credentials or tokens."
)


def _footer() -> str:
    return (
        "\n-- \n"
        "pkintel — passive phishing-kit intelligence (defensive research)\n"
        f"Reply-to / contact: {settings.takedown_from_email}\n"
    )


def _evidence_block(host_info: dict[str, Any] | None, kit_summary: dict[str, Any] | None) -> str:
    """Render a factual, redacted evidence block for host/registrar reports."""
    host_info = host_info or {}
    kit_summary = kit_summary or {}
    lines: list[str] = []
    if host_info.get("ip"):
        lines.append(f"  Resolved IP:   {host_info['ip']}")
    if host_info.get("asn"):
        asn_name = host_info.get("asn_name") or ""
        lines.append(f"  ASN:           AS{host_info['asn']} {asn_name}".rstrip())
    if host_info.get("country"):
        lines.append(f"  Country:       {host_info['country']}")
    if host_info.get("registrar"):
        lines.append(f"  Registrar:     {host_info['registrar']}")
    if kit_summary.get("brand"):
        lines.append(f"  Impersonates:  {kit_summary['brand']}")
    if kit_summary.get("sha256"):
        lines.append(f"  Kit archive (SHA-256): {kit_summary['sha256']}")
    if kit_summary.get("file_count"):
        lines.append(f"  Files in kit:  {kit_summary['file_count']}")
    for ind in kit_summary.get("indicators", []) or []:
        itype = ind.get("type", "indicator")
        disp = ind.get("redacted_display", "(redacted)")
        lines.append(f"  Exfil channel [{itype}]: {disp} (redacted)")
    return "\n".join(lines) if lines else "  (no additional technical evidence captured)"


def host_abuse_report(
    url: str,
    host_info: dict[str, Any] | None,
    kit_summary: dict[str, Any] | None,
) -> tuple[str, str]:
    """Report to a hosting provider's abuse desk requesting content removal."""
    host = host_info.get("hostname") if host_info else None
    host = host or url
    subject = f"[pkintel] Phishing content hosted on your network — takedown request ({url})"
    body = (
        "Hello,\n\n"
        "We are a defensive security research project and are reporting a "
        "confirmed phishing page hosted on infrastructure you appear to be "
        "responsible for. The site is very likely a compromised legitimate "
        "server; the owner is a victim too, and we ask you to treat it as such.\n\n"
        f"Phishing URL:\n  {url}\n\n"
        "Evidence:\n"
        f"{_evidence_block(host_info, kit_summary)}\n\n"
        "Request:\n"
        "  Please remove or suspend the phishing content (and, if present, the "
        "exposed kit archive and any results/log files) at the earliest "
        "opportunity, and consider notifying the account owner that their server "
        "was compromised.\n\n"
        f"{_REDACTION_NOTE}\n\n"
        f"{_PASSIVE_NOTE}\n"
        f"{_footer()}"
    )
    return subject, body


def registrar_report(
    url: str,
    host_info: dict[str, Any] | None,
    kit_summary: dict[str, Any] | None,
) -> tuple[str, str]:
    """Report to a domain registrar requesting suspension of a malicious domain."""
    registrar = (host_info or {}).get("registrar") or "the registrar"
    subject = f"[pkintel] Malicious domain used for phishing — suspension request ({url})"
    body = (
        f"Hello {registrar},\n\n"
        "We are a defensive security research project reporting a domain under "
        "your management that is being used to serve a confirmed phishing page.\n\n"
        f"Phishing URL:\n  {url}\n\n"
        "Evidence:\n"
        f"{_evidence_block(host_info, kit_summary)}\n\n"
        "Request:\n"
        "  Please review the registration and consider suspending the domain in "
        "line with your anti-abuse policy and the ICANN registrar accreditation "
        "agreement.\n\n"
        f"{_REDACTION_NOTE}\n\n"
        f"{_PASSIVE_NOTE}\n"
        f"{_footer()}"
    )
    return subject, body


def telegram_report(indicator_redacted_display: str, kit_sha: str | None) -> tuple[str, str]:
    """Report a Telegram bot token used for exfiltration — REPORT ONLY.

    The body carries the **redacted** token and states unambiguously that we
    have not and will not interact with the bot. We never place the full token
    in the body.
    """
    kit_ref = kit_sha or "(kit archive on file)"
    subject = "[pkintel] Abuse report: Telegram bot token used for phishing exfiltration"
    body = (
        "Hello Telegram Abuse Team,\n\n"
        "During static analysis of a phishing kit we found a Telegram bot token "
        "hard-coded as the exfiltration channel for stolen victim credentials. "
        "We are reporting the token so the bot can be disabled.\n\n"
        "Details:\n"
        f"  Bot token (REDACTED): {indicator_redacted_display}\n"
        f"  Found in phishing kit (SHA-256): {kit_ref}\n\n"
        "IMPORTANT — how we handled this:\n"
        "  We have not interacted with this bot and will not interact with it. "
        "We have made no call to the Telegram Bot API, have sent or read no "
        "messages, and have not used the token in any way. This finding is based "
        "solely on static inspection of the kit's source code. Using the token "
        "would mean touching real victims' data, which we will not do.\n\n"
        "Request:\n"
        "  Please disable the bot associated with this token so it can no longer "
        "receive exfiltrated credentials.\n\n"
        f"{_REDACTION_NOTE}\n\n"
        f"{_PASSIVE_NOTE}\n"
        f"{_footer()}"
    )
    return subject, body


def gsb_report(url: str) -> tuple[str, str]:
    """Build a Google Safe Browsing submission record for a malicious URL."""
    subject = "[pkintel] Malicious URL submission — Google Safe Browsing"
    body = (
        "Submitting a confirmed phishing URL to Google Safe Browsing so browsers "
        "can warn users before they reach it.\n\n"
        f"Phishing URL:\n  {url}\n\n"
        "Classification: SOCIAL_ENGINEERING (phishing).\n\n"
        f"{_PASSIVE_NOTE}\n"
        f"{_footer()}"
    )
    return subject, body


def apwg_report(url: str) -> tuple[str, str]:
    """Build an APWG eCrime Exchange submission record for a malicious URL."""
    subject = "[pkintel] Phishing URL report — APWG eCrime Exchange"
    body = (
        "Reporting a confirmed phishing URL to the APWG eCrime Exchange for "
        "inclusion in anti-phishing block lists and intelligence sharing.\n\n"
        f"Phishing URL:\n  {url}\n\n"
        f"{_PASSIVE_NOTE}\n"
        f"{_footer()}"
    )
    return subject, body
