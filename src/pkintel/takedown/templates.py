"""Pure abuse-report builders — Crisp Corporate Security Advisory Standard.

Short, factual, neutral, and structured like advisories from CrowdStrike,
Netcraft, and Cloudflare. Avoids conversational fluff that triggers spam filters.
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
    """Defang a hostname for display in email subjects/headers."""
    if not host:
        return "network-endpoint"
    h = host
    for prefix in ("https://", "http://", "hXXps://", "hXXp://"):
        if h.startswith(prefix):
            h = h[len(prefix):]
    if "/" in h:
        h = h.split("/", 1)[0]
    return h.replace(".", "[.]")


def _case_id(url: str) -> str:
    """Generate a stable case reference string for the report."""
    h = abs(hash(url)) % 90000 + 10000
    return f"OP-2026-{h}"


def _footer() -> str:
    return (
        "\n\n"
        "Outpost Threat Intelligence Operations\n"
        "HeapLeap Cyber Defense Team\n"
        f"Contact: {settings.takedown_from_email}"
    )


def _evidence_lines(host_info: dict[str, Any] | None, kit_summary: dict[str, Any] | None) -> list[str]:
    """Render factual technical evidence lines."""
    host_info = host_info or {}
    kit_summary = kit_summary or {}
    lines: list[str] = []

    if host_info.get("ip"):
        lines.append(f"  IP Address:      {host_info['ip']}")
    if host_info.get("asn"):
        asn_name = host_info.get("asn_name") or ""
        lines.append(f"  Network (ASN):    AS{host_info['asn']} {asn_name}".rstrip())
    if host_info.get("country"):
        lines.append(f"  Host Country:    {host_info['country']}")
    if host_info.get("registrar"):
        lines.append(f"  Registrar:       {host_info['registrar']}")
    if kit_summary.get("brand"):
        lines.append(f"  Target Brand:    {kit_summary['brand']}")
    if kit_summary.get("sha256"):
        lines.append(f"  Kit Hash (SHA):  {kit_summary['sha256']}")

    return lines


def host_abuse_report(
    url: str,
    host_info: dict[str, Any] | None,
    kit_summary: dict[str, Any] | None,
) -> tuple[str, str]:
    """Clean, neutral report to a hosting provider's security desk."""
    d_url = defang_url(url)
    host_info = host_info or {}
    hostname = host_info.get("hostname") or host_info.get("host")
    if not hostname:
        clean_u = url.replace("https://", "").replace("http://", "")
        hostname = clean_u.split("/", 1)[0]
    d_host = defang_host(hostname)
    cid = _case_id(url)

    subject = f"Security Incident Notification [{cid}] - Phishing on {d_host}"

    ev_lines = _evidence_lines(host_info, kit_summary)
    ev_text = "\n".join(ev_lines) if ev_lines else "  No additional host metadata"

    body = (
        "To: Network Security & Abuse Operations Team\n\n"
        f"Security Advisory | Reference: {cid}\n"
        f"Target Host: {d_host}\n\n"
        "Incident Summary:\n"
        "An active phishing page targeting user credentials has been identified on your hosting network.\n\n"
        "Technical Details:\n"
        f"  Case ID:         {cid}\n"
        f"  Classification:  Phishing / Social Engineering\n"
        f"  Defanged URL:    {d_url}\n"
        f"{ev_text}\n\n"
        "Recommended Action:\n"
        "Please review the reported URL and suspend the malicious content if verified.\n\n"
        "Notice: Technical indicators above are defanged for safe handling. "
        "This report was generated via passive threat monitoring."
        f"{_footer()}"
    )
    return subject, body


def registrar_report(
    url: str,
    host_info: dict[str, Any] | None,
    kit_summary: dict[str, Any] | None,
) -> tuple[str, str]:
    """Clean, neutral report to a domain registrar."""
    registrar = (host_info or {}).get("registrar") or "Registrar Operations"
    d_url = defang_url(url)
    hostname = (host_info or {}).get("hostname") or url
    d_host = defang_host(hostname)
    cid = _case_id(url)

    subject = f"Domain Security Notification [{cid}] - {d_host}"

    ev_lines = _evidence_lines(host_info, kit_summary)
    ev_text = "\n".join(ev_lines) if ev_lines else "  No additional registrar metadata"

    body = (
        f"To: {registrar} — Abuse & Compliance Desk\n\n"
        f"Security Advisory | Reference: {cid}\n"
        f"Target Domain: {d_host}\n\n"
        "Incident Summary:\n"
        "A domain registered under your management is currently serving active phishing content.\n\n"
        "Technical Details:\n"
        f"  Case ID:         {cid}\n"
        f"  Classification:  Phishing / Domain Misuse\n"
        f"  Defanged URL:    {d_url}\n"
        f"{ev_text}\n\n"
        "Recommended Action:\n"
        "Please review the domain registration and consider taking appropriate action per your AUP.\n\n"
        "Notice: All URLs are defanged for safe transit."
        f"{_footer()}"
    )
    return subject, body


def telegram_report(indicator_redacted_display: str, kit_sha: str | None) -> tuple[str, str]:
    """Clean report to Telegram abuse team."""
    kit_ref = kit_sha or "(analyzed threat archive)"
    cid = f"OP-TG-{abs(hash(indicator_redacted_display)) % 90000 + 10000}"
    subject = f"Threat Notification [{cid}] - Telegram Bot Token Misuse"
    body = (
        f"Security Advisory | Reference: {cid}\n"
        "Recipient: Telegram Trust & Safety\n\n"
        "Incident Summary:\n"
        "Static code analysis of a phishing kit identified a Telegram bot token used as an exfiltration endpoint.\n\n"
        "Technical Details:\n"
        f"  Case ID:         {cid}\n"
        f"  Bot Token:       {indicator_redacted_display} (Redacted)\n"
        f"  Kit Hash (SHA):  {kit_ref}\n\n"
        "Recommended Action:\n"
        "Please review and consider disabling the associated bot token.\n\n"
        "Notice: This finding is based solely on static code analysis. No API calls were made to Telegram."
        f"{_footer()}"
    )
    return subject, body


def gsb_report(url: str) -> tuple[str, str]:
    """Google Safe Browsing submission."""
    d_url = defang_url(url)
    cid = _case_id(url)
    subject = f"Safe Browsing Submission [{cid}] - Phishing URL"
    body = (
        f"Submission Ref: {cid}\n"
        f"URL: {d_url}\n"
        "Type: SOCIAL_ENGINEERING\n"
        f"{_footer()}"
    )
    return subject, body


def apwg_report(url: str) -> tuple[str, str]:
    """APWG report."""
    d_url = defang_url(url)
    cid = _case_id(url)
    subject = f"APWG Submission [{cid}] - Phishing URL"
    body = (
        f"Submission Ref: {cid}\n"
        f"URL: {d_url}\n"
        f"{_footer()}"
    )
    return subject, body
