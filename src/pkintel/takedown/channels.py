"""Multi-Channel Takedown Dispatchers for Phishing URLs.

Dispatches confirmed phishing URLs and evidence packages to external threat intelligence
and abuse intake channels:
1. Google Safe Browsing / Web Risk Report
2. PhishTank Submission Intake
3. Netcraft Malicious URL Intake
4. aeCERT (aeCERT Incidents Desk via Email)
5. APWG (Anti-Phishing Working Group)
"""

from __future__ import annotations

from typing import Any

import httpx

from pkintel.logging import get_logger
from pkintel.takedown.mailer import send_takedown_email

log = get_logger(__name__)


def dispatch_safe_browsing(url: str) -> bool:
    """Dispatch phishing URL report to Google Safe Browsing submission endpoint."""
    from pkintel.config import settings

    api_key = getattr(settings, "gsb_api_key", "") or ""
    if not api_key:
        log.info("safe_browsing_skipped_no_key", url=url)
        return False
    endpoint = f"https://webrisk.googleapis.com/v1/uris:submit?key={api_key}"
    payload = {"submission": {"uri": url}}
    try:
        with httpx.Client(timeout=10.0, follow_redirects=True) as client:
            resp = client.post(endpoint, json=payload)
            if resp.status_code in (200, 201, 302):
                log.info("dispatched_safe_browsing", url=url, status=resp.status_code)
                return True
            log.warning("safe_browsing_failed", url=url, status=resp.status_code)
            return False
    except Exception as e:
        log.warning("safe_browsing_error", url=url, error=str(e))
        return False


def dispatch_phishtank(url: str) -> bool:
    """Dispatch phishing URL to PhishTank submission endpoint."""
    from pkintel.config import settings

    api_key = getattr(settings, "phishtank_api_key", "") or ""
    if not api_key:
        log.info("phishtank_skipped_no_key", url=url)
        return False
    target_api = "https://www.phishtank.com/add_web_phish.php"
    try:
        with httpx.Client(timeout=10.0, follow_redirects=True) as client:
            resp = client.post(target_api, data={"url": url, "is_phish": "yes", "app_key": api_key})
            if resp.status_code in (200, 302):
                log.info("dispatched_phishtank", url=url, status=resp.status_code)
                return True
            log.warning("phishtank_dispatch_failed", url=url, status=resp.status_code)
            return False
    except Exception as e:
        log.warning("phishtank_dispatch_error", url=url, error=str(e))
        return False


def dispatch_netcraft(url: str) -> bool:
    """Dispatch phishing URL to Netcraft report API."""
    from pkintel.config import settings

    api_key = getattr(settings, "netcraft_api_key", "") or ""
    if not api_key:
        log.info("netcraft_skipped_no_key", url=url)
        return False
    target_api = "https://report.netcraft.com/api/v3/report/urls"
    try:
        payload = {"urls": [{"url": url}]}
        headers = {"Authorization": f"Bearer {api_key}"}
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(target_api, json=payload, headers=headers)
            if resp.status_code in (200, 201, 202):
                log.info("dispatched_netcraft", url=url, status=resp.status_code)
                return True
            log.warning("netcraft_dispatch_failed", url=url, status=resp.status_code)
            return False
    except Exception as e:
        log.warning("netcraft_dispatch_error", url=url, error=str(e))
        return False


def dispatch_aecert(url: str, notice_body: str = "") -> bool:
    """Dispatch UAE phishing incident report to aeCERT (incidents@aecert.ae)."""
    # Disabled: incidents@aecert.ae bounces with 550 User Unknown.
    log.info("aecert_dispatch_disabled", url=url)
    return False


def dispatch_apwg(url: str, evidence: dict[str, Any] | None = None) -> bool:
    """Dispatch phishing report to APWG (Anti-Phishing Working Group) eCrime Intake."""
    subject = f"[APWG Phish Report] {url}"
    attachments_summary = ""
    if evidence and "attachments" in evidence:
        attachments_summary = f"\nEvidence attachments: {len(evidence['attachments'])} items."

    body = (
        f"APWG eCrime Intake,\n\n"
        f"Automated phishing detection report:\n"
        f"Target URL: {url}\n"
        f"{attachments_summary}\n\n"
        f"-- Outpost Automated Takedown Engine"
    )
    try:
        send_takedown_email("reportphishing@apwg.org", subject, body)
        log.info("dispatched_apwg", url=url)
        return True
    except Exception as e:
        log.warning("apwg_dispatch_error", url=url, error=str(e))
        return False


def dispatch_all_channels(
    url: str, notice: dict[str, Any] | None = None, evidence: dict[str, Any] | None = None
) -> list[str]:
    """Dispatch takedown requests to all configured intake channels.

    Returns a list of channels that successfully accepted the submission.
    """
    successful_channels: list[str] = []

    if dispatch_safe_browsing(url):
        successful_channels.append("safe_browsing")

    if dispatch_phishtank(url):
        successful_channels.append("phishtank")

    if dispatch_netcraft(url):
        successful_channels.append("netcraft")

    if dispatch_aecert(url, (notice or {}).get("body", "")):
        successful_channels.append("aecert")

    if dispatch_apwg(url, evidence):
        successful_channels.append("apwg")

    return successful_channels
