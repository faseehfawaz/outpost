"""Pure abuse-report builders — Enterprise Threat Intelligence & CSIRT Standard.

Each function returns a ``(subject, body)`` tuple for automated dispatch to
network abuse operations, domain registrars, and security teams.
"""

from __future__ import annotations

from typing import Any

from pkintel.config import settings

# Standing abuse-desk contacts
TELEGRAM_ABUSE_CONTACT = "abuse@telegram.org"
APWG_CONTACT = "reports@apwg.org"
GSB_CONTACT = "Google Safe Browsing"
AECERT_CONTACT = "aeCERT (TDRA)"

_PASSIVE_NOTE = (
    "NOTICE OF PASSIVE RESEARCH & ETHICAL SCOPE:\n"
    "This advisory was produced strictly via passive, non-intrusive threat intelligence\n"
    "collection. No authentication, brute-forcing, vulnerability exploitation, or\n"
    "interaction with victim data / attacker infrastructure was performed."
)

_REDACTION_NOTE = (
    "DATA PRIVACY & REDACTION:\n"
    "All technical indicators in this advisory are REDACTED for safe email transit.\n"
    "Verified abuse response personnel may request full un-redacted evidence via\n"
    "secure channels."
)


def defang_url(url: str) -> str:
    """Defang a URL for safe email transmission (defangs scheme and domain dots).

    Example:
        https://facebook-login.vercel.app/path -> hXXps://facebook-login[.]vercel[.]app/path
    """
    if not url:
        return ""
    u = url.replace("https://", "hXXps://").replace("http://", "hXXp://")
    if "://" in u:
        scheme, rest = u.split("://", 1)
        if "/" in rest:
            host, path = rest.split("/", 1)
            defanged_host = host.replace(".", "[.]")
            return f"{scheme}://{defanged_host}/{path}"
        return f"{scheme}://{rest.replace('.', '[.]')}"
    return u.replace(".", "[.]")


def _footer() -> str:
    return (
        "\n"
        "----------------------------------------------------------------------\n"
        "Outpost Threat Intelligence Center | HeapLeap Cyber Defense\n"
        f"Official Contact: {settings.takedown_from_email}\n"
        "Defensive Research & Automated Threat Remediation\n"
        "----------------------------------------------------------------------\n"
    )


def _evidence_block(host_info: dict[str, Any] | None, kit_summary: dict[str, Any] | None) -> str:
    """Render a structured, monospaced evidence block for enterprise CSIRT reports."""
    host_info = host_info or {}
    kit_summary = kit_summary or {}
    lines: list[str] = []

    if host_info.get("ip"):
        lines.append(f"  Target IPv4 Address: {host_info['ip']}")
    if host_info.get("asn"):
        asn_name = host_info.get("asn_name") or ""
        lines.append(f"  Autonomous System:   AS{host_info['asn']} ({asn_name})".rstrip())
    if host_info.get("country"):
        lines.append(f"  Hosting Location:    {host_info['country']}")
    if host_info.get("registrar"):
        lines.append(f"  Domain Registrar:    {host_info['registrar']}")
    if kit_summary.get("brand"):
        lines.append(f"  Targeted Brand:      {kit_summary['brand']}")
    if kit_summary.get("sha256"):
        lines.append(f"  Kit Signature (SHA): {kit_summary['sha256']}")
    if kit_summary.get("file_count"):
        lines.append(f"  Phishing Kit Files:  {kit_summary['file_count']}")

    for ind in kit_summary.get("indicators", []) or []:
        itype = ind.get("type", "indicator")
        disp = ind.get("redacted_display", "(redacted)")
        lines.append(f"  Exfiltration Channel [{itype}]: {disp} [REDACTED]")

    return "\n".join(lines) if lines else "  (Standard technical evidence captured)"


def host_abuse_report(
    url: str,
    host_info: dict[str, Any] | None,
    kit_summary: dict[str, Any] | None,
) -> tuple[str, str]:
    """Enterprise report to a hosting provider's abuse desk requesting content removal."""
    d_url = defang_url(url)
    subject = f"[ABUSE ADVISORY] Active Phishing Endpoint Incident — {d_url}"
    body = (
        "ATTN: Network Operations & Security Response Team\n\n"
        "This is an automated threat intelligence advisory regarding a confirmed active "
        "phishing endpoint detected on infrastructure assigned to your organization.\n\n"
        "======================================================================\n"
        "INCIDENT TECHNICAL SUMMARY\n"
        "======================================================================\n"
        f"  Flagged Endpoint (Defanged): {d_url}\n"
        f"{_evidence_block(host_info, kit_summary)}\n"
        "  Threat Classification:        HIGH — Social Engineering / Credential Theft\n\n"
        "======================================================================\n"
        "REMEDIATION ACTION REQUESTED\n"
        "======================================================================\n"
        "  1. Suspend or isolate the flagged URL endpoint to prevent victim impact.\n"
        "  2. Remove any deployed exfiltration scripts or exposed kit archives.\n"
        "  3. Notify the account holder regarding potential credential/server compromise.\n\n"
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
    """Enterprise report to a domain registrar requesting suspension of a malicious domain."""
    registrar = (host_info or {}).get("registrar") or "Registrar Abuse Desk"
    d_url = defang_url(url)
    subject = f"[REGISTRAR ADVISORY] Malicious Domain Suspension Request — {d_url}"
    body = (
        f"ATTN: {registrar} — Abuse & Compliance Operations\n\n"
        "This is an automated threat intelligence report concerning a domain registered "
        "under your organization that is currently engaging in malicious phishing activity.\n\n"
        "======================================================================\n"
        "MALICIOUS DOMAIN IDENTIFICATION\n"
        "======================================================================\n"
        f"  Flagged Domain / URL (Defanged): {d_url}\n"
        f"{_evidence_block(host_info, kit_summary)}\n"
        "  Classification:                   Phishing / Brand Impersonation\n\n"
        "======================================================================\n"
        "REQUESTED REGISTRAR ACTION\n"
        "======================================================================\n"
        "  Please review the domain registration and take appropriate suspension action "
        "in compliance with your Acceptable Use Policy and ICANN RAA obligations.\n\n"
        f"{_REDACTION_NOTE}\n\n"
        f"{_PASSIVE_NOTE}\n"
        f"{_footer()}"
    )
    return subject, body


def telegram_report(indicator_redacted_display: str, kit_sha: str | None) -> tuple[str, str]:
    """Report a Telegram bot token used for exfiltration — REPORT ONLY."""
    kit_ref = kit_sha or "(analyzed threat archive)"
    subject = "[SECURITY ADVISORY] Malicious Telegram Bot Token — Credential Exfiltration"
    body = (
        "ATTN: Telegram Trust & Safety / Abuse Team\n\n"
        "During threat analysis of an active phishing kit, a Telegram bot token was "
        "identified as an exfiltration endpoint for stolen user credentials.\n\n"
        "======================================================================\n"
        "EXFILTRATION BOT DETAILS\n"
        "======================================================================\n"
        f"  Bot Token Signature (REDACTED): {indicator_redacted_display}\n"
        f"  Source Phishing Kit Hash (SHA256): {kit_ref}\n\n"
        "SPECIAL HANDLING & PROTOCOL NOTICE:\n"
        "  Outpost threat operations has NOT executed, called, or interacted with "
        "this bot token in any capacity. This discovery is based solely on static "
        "code inspection.\n\n"
        "REQUESTED ACTION:\n"
        "  Please revoke/terminate the bot associated with this token to neutralize "
        "the exfiltration pipeline.\n\n"
        f"{_REDACTION_NOTE}\n\n"
        f"{_PASSIVE_NOTE}\n"
        f"{_footer()}"
    )
    return subject, body


def gsb_report(url: str) -> tuple[str, str]:
    """Build a Google Safe Browsing submission record for a malicious URL."""
    d_url = defang_url(url)
    subject = f"[SAFE BROWSING SUBMISSION] Malicious URL — {d_url}"
    body = (
        "Submitting a verified phishing URL to Google Safe Browsing.\n\n"
        f"Target URL (Defanged): {d_url}\n"
        "Threat Type:            SOCIAL_ENGINEERING (Phishing)\n\n"
        f"{_PASSIVE_NOTE}\n"
        f"{_footer()}"
    )
    return subject, body


def apwg_report(url: str) -> tuple[str, str]:
    """Build an APWG eCrime Exchange submission record for a malicious URL."""
    d_url = defang_url(url)
    subject = f"[APWG THREAT FEED] Phishing URL Report — {d_url}"
    body = (
        "Submitting a verified phishing URL to the APWG eCrime Exchange.\n\n"
        f"Target URL (Defanged): {d_url}\n\n"
        f"{_PASSIVE_NOTE}\n"
        f"{_footer()}"
    )
    return subject, body
