"""Playwright Headless Browser and API-based Form Submission Engine.

Automates the submission of phishing URLs to web forms and REST APIs.
"""

from __future__ import annotations

from typing import Any

import httpx
from playwright.sync_api import sync_playwright

from pkintel.config import settings
from pkintel.logging import get_logger

log = get_logger(__name__)


def submit_via_playwright(form_config: dict[str, Any], target_url: str, body: str) -> bool:
    """Automate form completion using a headless Playwright Chromium instance."""
    url = form_config["url"]
    fields = form_config["fields"]
    reporter_email = settings.takedown_from_email or "abuse@heapleap.tech"

    log.info("playwright_form_submission_started", provider_url=url, target_url=target_url)

    try:
        with sync_playwright() as p:
            # Launch browser
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(viewport={"width": 1280, "height": 800})
            page = context.new_page()

            # Go to abuse form
            page.goto(url, timeout=20000, wait_until="domcontentloaded")

            # Fill in the URL
            if "url_selector" in fields:
                page.wait_for_selector(fields["url_selector"], timeout=5000)
                page.fill(fields["url_selector"], target_url)

            # Fill in reporter email
            if "email_selector" in fields:
                page.wait_for_selector(fields["email_selector"], timeout=5000)
                page.fill(fields["email_selector"], reporter_email)

            # Fill in reporter name
            if "name_selector" in fields:
                page.wait_for_selector(fields["name_selector"], timeout=5000)
                page.fill(fields["name_selector"], "Heapleap Security Operations")

            # Fill in the details/body justification
            if "details_selector" in fields:
                page.wait_for_selector(fields["details_selector"], timeout=5000)
                page.fill(fields["details_selector"], body)

            # Click submit button
            if "submit_selector" in fields:
                page.wait_for_selector(fields["submit_selector"], timeout=5000)
                
                # In dry run mode, we do NOT click submit to avoid polluting real endpoints
                if settings.takedown_dry_run:
                    log.info("dry_run_submit_skipped", provider_url=url)
                    browser.close()
                    return True

                page.click(fields["submit_selector"])
                # Wait for network responses to finish
                try:
                    page.wait_for_load_state("networkidle", timeout=8000)
                except Exception:
                    pass

            log.info("playwright_form_submission_success", provider_url=url)
            browser.close()
            return True

    except Exception as e:
        log.warning("playwright_submission_failed", provider_url=url, error=str(e))
        return False


def submit_via_http_post(form_config: dict[str, Any], target_url: str) -> bool:
    """Submit report to simple HTML form endpoints via HTTP POST."""
    url = form_config["url"]
    fields = form_config["fields"]

    data = {
        fields["url_field"]: target_url,
    }
    if "extra_data" in fields:
        data.update(fields["extra_data"])

    log.info("http_post_submission_started", provider_url=url, target_url=target_url)

    if settings.takedown_dry_run:
        log.info("dry_run_http_post_skipped", provider_url=url)
        return True

    try:
        with httpx.Client(timeout=10.0, follow_redirects=True) as client:
            resp = client.post(url, data=data)
            if resp.status_code in (200, 201, 302):
                log.info("http_post_submission_success", provider_url=url, status=resp.status_code)
                return True
            log.warning("http_post_submission_failed_status", provider_url=url, status=resp.status_code)
            return False
    except Exception as e:
        log.warning("http_post_submission_error", provider_url=url, error=str(e))
        return False


def submit_via_api(form_config: dict[str, Any], target_url: str, evidence: dict[str, Any] | None = None) -> bool:
    """Submit report to API endpoints via JSON payload."""
    url = form_config["url"]
    fields = form_config["fields"]

    payload = {
        fields["payload_key"]: [{"url": target_url}]
    }

    log.info("api_submission_started", provider_url=url, target_url=target_url)

    if settings.takedown_dry_run:
        log.info("dry_run_api_skipped", provider_url=url)
        return True

    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(url, json=payload)
            if resp.status_code in (200, 201, 202):
                log.info("api_submission_success", provider_url=url, status=resp.status_code)
                return True
            log.warning("api_submission_failed_status", provider_url=url, status=resp.status_code)
            return False
    except Exception as e:
        log.warning("api_submission_error", provider_url=url, error=str(e))
        return False
