"""Pure abuse-report builders — Clean, Natural Security Notification Standard.

Designed to pass email spam filters (no all-caps triggers, no ASCII art lines,
no URLs in subject lines, and clean human-readable defanging).
"""

from __future__ import annotations

from typing import Any

from pkintel.config import settings

# Standing abuse-desk contacts
TELEGRAM_ABUSE_CONTACT = "abuse@telegram.org"
APWG_CONTACT = "reports@apwg.org"
GSB_CONTACT = "Google Safe Browsing"
AECERT_CONTACT = "aeCERT (TDRA)"


def defang_url(url: str) -> str:
    """Defang a URL cleanly for email transit.

    Example:
        https://facebook-login.vercel.app/path -> https://facebook-login[.]vercel[.]app/path
    """
    if not url:
        return ""
    u = url
    if "://" in u:
        scheme, rest = u.split("://", 1)
        if "/" in rest:
            host, path = rest.split("/", 1)
            defanged_host = host.replace(".", "[.]")
            return f"{scheme}://{defanged_host}/{path}"
        return f"{scheme}://{rest.replace('.', '[.]')}"
    return u.replace(".", "[.]")


def defang_host(host: str) -> str:
    """Defang a hostname for display in email subjects/headers (strips scheme and paths)."""
    if not host:
        return "target network"
    h = host
    for prefix in ("https://", "http://", "hXXps://", "hXXp://"):
        if h.startswith(prefix):
            h = h[len(prefix):]
    if "/" in h:
        h = h.split("/", 1)[0]
    return h.replace(".", "[.]")


def _footer() -> str:
    return (
        "\n\n---\n"
        "Security Team | Outpost Threat Intelligence\n"
        f"Contact: {settings.takedown_from_email}\n"
        "HeapLeap Cyber Defense Operations"
    )


def _evidence_block(host_info: dict[str, Any] | None, kit_summary: dict[str, Any] | None) -> str:
    """Render a clean, natural technical evidence block."""
    host_info = host_info or {}
    kit_summary = kit_summary or {}
    lines: list[str] = []

    if host_info.get("ip"):
        lines.append(f"  • IP Address: {host_info['ip']}")
    if host_info.get("asn"):
        asn_name = host_info.get("asn_name") or ""
        lines.append(f"  • Network (ASN): AS{host_info['asn']} {asn_name}".rstrip())
    if host_info.get("country"):
        lines.append(f"  • Host Location: {host_info['country']}")
    if host_info.get("registrar"):
        lines.append(f"  • Domain Registrar: {host_info['registrar']}")
    if kit_summary.get("brand"):
        lines.append(f"  • Targeted Brand: {kit_summary['brand']}")
    if kit_summary.get("sha256"):
        lines.append(f"  • Threat Signature: {kit_summary['sha256']}")

    return "\n".join(lines) if lines else "  • Standard technical evidence captured"


def host_abuse_report(
    url: str,
    host_info: dict[str, Any] | None,
    kit_summary: dict[str, Any] | None,
) -> tuple[str, str]:
    """Clean report to a hosting provider's abuse team."""
    d_url = defang_url(url)
    host_info = host_info or {}
    hostname = host_info.get("hostname") or host_info.get("host")
    if not hostname:
        clean_u = url.replace("https://", "").replace("http://", "")
        hostname = clean_u.split("/", 1)[0]
    d_host = defang_host(hostname)

    subject = f"Security Notice: Phishing activity reported on {d_host}"
    body = (
        "Hello Abuse & Security Team,\n\n"
        "We are writing to notify your team regarding a confirmed phishing page currently "
        "hosted on your network infrastructure.\n\n"
        f"Reported Page (Defanged):\n  {d_url}\n\n"
        "Technical Details:\n"
        f"{_evidence_block(host_info, kit_summary)}\n\n"
        "Action Requested:\n"
        "Could you please review this endpoint and suspend or remove the malicious content "
        "at your earliest convenience? If the site belongs to a legitimate customer whose server "
        "was compromised, we recommend notifying the account owner so they can secure it.\n\n"
        "Note: Technical indicators above are defanged for safe handling. "
        "Our research is strictly passive and rate-limited.\n"
        f"{_footer()}"
    )
    return subject, body


def registrar_report(
    url: str,
    host_info: dict[str, Any] | None,
    kit_summary: dict[str, Any] | None,
) -> tuple[str, str]:
    """Clean report to a domain registrar."""
    registrar = (host_info or {}).get("registrar") or "Registrar Team"
    d_url = defang_url(url)
    hostname = (host_info or {}).get("hostname") or url
    d_host = defang_host(hostname)

    subject = f"Domain Security Notice: Phishing activity on {d_host}"
    body = (
        f"Hello {registrar},\n\n"
        "We are writing to inform your compliance team about a domain registered under "
        "your management that is currently serving active phishing content.\n\n"
        f"Reported URL (Defanged):\n  {d_url}\n\n"
        "Technical Details:\n"
        f"{_evidence_block(host_info, kit_summary)}\n\n"
        "Action Requested:\n"
        "We kindly request that you review the domain registration and consider taking appropriate "
        "action according to your acceptable use policy.\n\n"
        "Note: All URLs and indicators are defanged for safe email transit.\n"
        f"{_footer()}"
    )
    return subject, body


def telegram_report(indicator_redacted_display: str, kit_sha: str | None) -> tuple[str, str]:
    """Clean report to Telegram abuse team."""
    kit_ref = kit_sha or "(analyzed threat archive)"
    subject = "Security Notice: Malicious bot token identified in phishing campaign"
    body = (
        "Hello Telegram Security Team,\n\n"
        "During static analysis of a phishing kit, we identified a Telegram bot token "
        "being used as an automated exfiltration channel for stolen credentials.\n\n"
        "Bot Details:\n"
        f"  • Token (Redacted): {indicator_redacted_display}\n"
        f"  • Source Signature: {kit_ref}\n\n"
        "Action Requested:\n"
        "Please review and consider disabling this bot token to stop further credential exfiltration.\n\n"
        "Our research is strictly static and passive. We have not interacted with or executed calls "
        "to this bot.\n"
        f"{_footer()}"
    )
    return subject, body


def gsb_report(url: str) -> tuple[str, str]:
    """Google Safe Browsing submission."""
    d_url = defang_url(url)
    subject = f"Safe Browsing Submission: Phishing URL ({d_url})"
    body = (
        "Submitting a confirmed phishing URL for Google Safe Browsing index.\n\n"
        f"URL: {d_url}\n"
        "Classification: Phishing / Social Engineering\n"
        f"{_footer()}"
    )
    return subject, body


def apwg_report(url: str) -> tuple[str, str]:
    """APWG report."""
    d_url = defang_url(url)
    subject = f"APWG Submission: Phishing URL ({d_url})"
    body = (
        "Submitting a confirmed phishing URL for APWG blocklist inclusion.\n\n"
        f"URL: {d_url}\n"
        f"{_footer()}"
    )
    return subject, body
