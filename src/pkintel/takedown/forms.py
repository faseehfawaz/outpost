"""Provider Registry and Dispatch Routing for Web-based Abuse Forms.

Matches hosting providers/registrars by name, ASN, or abuse email domain to
determine if they prefer web form submissions. Route submissions through
Playwright or HTTP POST.
"""

from __future__ import annotations

from typing import Any

from pkintel.logging import get_logger
from pkintel.takedown.form_submit import submit_via_api, submit_via_http_post, submit_via_playwright

log = get_logger(__name__)

# Registry mapping providers to their form layout configurations.
PROVIDER_FORMS: dict[str, dict[str, Any]] = {
    "cloudflare": {
        "match_keywords": ["cloudflare", "as13335"],
        "url": "https://abuse.cloudflare.com/phishing",
        "method": "playwright",
        "fields": {
            "url_selector": "input[name='urls'], textarea[name='urls']",
            "email_selector": "input[name='email']",
            "name_selector": "input[name='name']",
            "details_selector": "textarea[name='justification']",
            "submit_selector": "button[type='submit']",
        },
    },
    "godaddy": {
        "match_keywords": ["godaddy", "wild west domains", "as26496"],
        "url": "https://supportcenter.godaddy.com/abuse",
        "method": "playwright",
        "fields": {
            "url_selector": "input[name='abuse_url'], textarea[name='abuse_url']",
            "email_selector": "input[name='reporter_email']",
            "details_selector": "textarea[name='abuse_details']",
            "submit_selector": "button[type='submit']",
        },
    },
    "namecheap": {
        "match_keywords": ["namecheap", "as11854"],
        "url": "https://www.namecheap.com/support/abuse/",
        "method": "playwright",
        "fields": {
            "url_selector": "input[name='abuse_url']",
            "email_selector": "input[name='reporter_email']",
            "details_selector": "textarea[name='abuse_details']",
            "submit_selector": "button[type='submit']",
        },
    },
    "google_safebrowsing": {
        "match_keywords": ["google", "as15169", "as396982"],
        "url": "https://safebrowsing.google.com/safebrowsing/report_phish/",
        "method": "http_post",
        "fields": {
            "url_field": "url",
            "extra_data": {"submit": "Submit Report"},
        },
    },
    "netcraft": {
        "match_keywords": [],  # Used as secondary global channel (always called via api)
        "url": "https://report.netcraft.com/api/v3/report/urls",
        "method": "api_json",
        "fields": {
            "payload_key": "urls",
        },
    },
}


def identify_providers(host_info: dict[str, Any]) -> list[str]:
    """Identify which registered providers match the host enrichment.

    Args:
        host_info: Enriched host data (ip, abuse_email, registrar, asn, asn_name, country).

    Returns:
        List of matching keys in PROVIDER_FORMS.
    """
    matched: list[str] = []

    registrar = (host_info.get("registrar") or "").strip().lower()
    asn_name = (host_info.get("asn_name") or "").strip().lower()
    asn = str(host_info.get("asn") or "").strip().lower()
    abuse_email = (host_info.get("abuse_email") or "").strip().lower()

    # Extract abuse email domain (e.g. abuse@cloudflare.com -> cloudflare)
    abuse_domain = ""
    if "@" in abuse_email:
        abuse_domain = abuse_email.split("@")[-1].split(".")[0]

    for key, cfg in PROVIDER_FORMS.items():
        # Match keywords against registrar, asn_name, ASN ID, or abuse domain
        keywords = cfg.get("match_keywords", [])
        if not keywords:
            continue

        for kw in keywords:
            if (
                kw in registrar
                or kw in asn_name
                or kw == f"as{asn}"
                or (abuse_domain and kw == abuse_domain)
            ):
                matched.append(key)
                break

    return matched


def submit_abuse_form(
    provider_key: str,
    target_url: str,
    subject: str,
    body: str,
    evidence: dict[str, Any] | None = None,
) -> bool:
    """Submit the abuse report for a provider using its preferred intake method.

    Args:
        provider_key: Provider key in PROVIDER_FORMS.
        target_url: Phishing URL to take down.
        subject: Subject of the abuse report.
        body: Factual details/body of the report.
        evidence: Evidence package dict containing attachments.

    Returns:
        True if successfully submitted.
    """
    cfg = PROVIDER_FORMS.get(provider_key)
    if not cfg:
        log.warning("provider_not_found", provider_key=provider_key)
        return False

    method = cfg.get("method")
    url = cfg.get("url")
    fields = cfg.get("fields", {})

    log.info("submitting_abuse_form", provider=provider_key, url=url, method=method)

    try:
        if method == "playwright":
            return submit_via_playwright(cfg, target_url, body)
        elif method == "http_post":
            return submit_via_http_post(cfg, target_url)
        elif method == "api_json":
            return submit_via_api(cfg, target_url, evidence)
        else:
            log.warning("unknown_submission_method", method=method, provider=provider_key)
            return False
    except Exception as e:
        log.exception("abuse_form_submission_failed", provider=provider_key, error=str(e))
        return False
