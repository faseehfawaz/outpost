"""
Runner for the takedown pipeline.

Phase 1: Generates draft takedown abuse reports for confirmed phish URLs.
         Works with or without a collected kit — URL-based takedowns are
         generated for every phishing URL that does not yet have a takedown.
Phase 2: Sends draft takedowns (respecting dry-run settings).
"""

from pkintel.config import settings
from pkintel.crypto import decrypt_indicator
from pkintel.db import claim_rows, execute, fetch_all, record_audit
from pkintel.logging import get_logger
from pkintel.takedown.channels import dispatch_all_channels
from pkintel.takedown.evidence import build_evidence_package
from pkintel.takedown.forms import identify_providers, submit_abuse_form
from pkintel.takedown.mailer import send_takedown_email
from pkintel.takedown.rdap import enrich_host
from pkintel.takedown.templates import host_abuse_report, registrar_report, telegram_report

log = get_logger(__name__)


def run_once(worker_id: str = "takedown-1", limit: int = 50) -> int:
    """
    Run the takedown worker once.

    Phase 1: Sends draft takedowns (respecting dry-run settings) and dispatches
             multi-channel reports (Safe Browsing, PhishTank, Netcraft, aeCERT, APWG).
    Phase 2: Generates draft takedowns for phish URLs (kit optional).
    """
    processed_count = 0

    # --- Phase 1: Send Pending Drafts & Multi-Channel Dispatch ---
    drafts = claim_rows(
        "takedowns",
        ready_col="status",
        ready_value="draft",
        busy_value="sending",
        worker_id=worker_id,
        limit=limit,
        order_by="id",
    )
    for draft in drafts:
        draft_id = draft["id"]
        url_id = draft.get("url_id")
        contact = (draft.get("contact") or "").strip()

        if not contact or "localhost" in contact or "@" not in contact:
            log.info(
                "No valid abuse contact for takedown %s (%s), marking no_contact", draft_id, contact
            )
            execute("UPDATE takedowns SET status = 'no_contact' WHERE id = %s", (draft_id,))
            continue

        subject = draft.get("subject", "Phishing Takedown Notice")
        body = draft.get("body", "")

        try:
            # 1. Resolve host metadata to match against provider forms registry
            target_url = None
            host = None
            if url_id:
                url_rows = fetch_all("SELECT url, host FROM urls WHERE id = %s", (url_id,))
                if url_rows:
                    target_url = url_rows[0].get("url")
                    host = url_rows[0].get("host")

            host_info = {}
            if host:
                host_rows = fetch_all(
                    "SELECT hostname, ip, asn, asn_name, country, registrar, rdap_abuse_email FROM hosts WHERE hostname = %s",
                    (host,),
                )
                if host_rows:
                    r = host_rows[0]
                    host_info = {
                        "registrar": r.get("registrar"),
                        "asn_name": r.get("asn_name"),
                        "asn": r.get("asn"),
                        "abuse_email": r.get("rdap_abuse_email"),
                    }

            # 2. Check if provider uses a form-based intake
            providers = identify_providers(host_info) if host_info else []
            submitted_via_form = False
            actual_target = ""

            if providers and target_url:
                evidence = build_evidence_package(url_id)
                for provider_key in providers:
                    log.info(
                        "attempting_form_submission", provider=provider_key, takedown_id=draft_id
                    )
                    success = submit_abuse_form(provider_key, target_url, subject, body, evidence)
                    if success:
                        submitted_via_form = True
                        actual_target = f"form:{provider_key}"
                        new_status = "dry_run" if settings.takedown_dry_run else "sent"
                        # Update target_type to show form submission
                        execute(
                            "UPDATE takedowns SET target_type = %s WHERE id = %s",
                            (f"form:{provider_key}", draft_id),
                        )
                        log.info(
                            "form_submission_success", provider=provider_key, takedown_id=draft_id
                        )
                        break

            # 3. Fallback to SMTP if no form matched or form submission failed
            if not submitted_via_form:
                if settings.takedown_dry_run:
                    log.info("DRY RUN: Would send takedown %s to %s", draft_id, contact)
                    actual_target = contact
                    new_status = "dry_run"
                else:
                    log.info("Sending takedown %s via SMTP", draft_id)
                    actual_target = send_takedown_email(contact, subject, body)
                    new_status = "sent"

            # 4. Dispatch multi-channel feeds if we are sending live reports
            if new_status == "sent" and target_url:
                evidence = build_evidence_package(url_id)
                dispatched = dispatch_all_channels(
                    target_url, notice={"body": body}, evidence=evidence
                )
                log.info(
                    "multi_channel_dispatch_complete", takedown_id=draft_id, channels=dispatched
                )

            execute(
                "UPDATE takedowns SET status = %s, sent_at = now() WHERE id = %s",
                (
                    new_status,
                    draft_id,
                ),
            )
            processed_count += 1
            record_audit("takedown", new_status, actual_target, takedown_id=draft_id)

        except Exception as e:
            log.exception("Failed to send takedown %s: %s", draft_id, e)
            execute("UPDATE takedowns SET status = 'error' WHERE id = %s", (draft_id,))

    # --- Phase 2: Generate Drafts for New Phishing URLs ---
    query_drafts = """
        SELECT u.id, u.url, u.host
        FROM urls u
        LEFT JOIN takedowns t ON u.id = t.url_id
        WHERE u.is_phish = true AND t.id IS NULL
        LIMIT %s
    """
    urls_to_draft = fetch_all(query_drafts, (10,))

    for url_row in urls_to_draft:
        try:
            url_id = url_row["id"]
            url = url_row["url"]
            host = url_row["host"]

            host_info = enrich_host(host)

            kit_id = None
            kit_sha = None
            try:
                kit_query = """
                    SELECT k.id, k.sha256 
                    FROM kits k 
                    WHERE k.url_id = %s
                    LIMIT 1
                """
                kits = fetch_all(kit_query, (url_id,))
                if kits:
                    kit_id = kits[0]["id"]
                    kit_sha = kits[0]["sha256"]
            except Exception:
                pass

            kit_summary = {"sha256": kit_sha, "count": 1 if kit_id else 0}

            # 1. Host Abuse Report
            h_sub, h_body = host_abuse_report(url, host_info, kit_summary)
            h_contact = host_info.get("abuse_email") or "abuse@localhost"
            execute(
                """
                INSERT INTO takedowns (url_id, kit_id, target_type, contact, subject, body, status)
                VALUES (%s, %s, 'host', %s, %s, %s, 'draft')
                ON CONFLICT DO NOTHING
                """,
                (url_id, kit_id, h_contact, h_sub, h_body),
            )

            # 2. Registrar Abuse Report
            r_sub, r_body = registrar_report(url, host_info, kit_summary)
            r_contact = host_info.get("registrar_abuse_email") or "abuse@localhost"
            execute(
                """
                INSERT INTO takedowns (url_id, kit_id, target_type, contact, subject, body, status)
                VALUES (%s, %s, 'registrar', %s, %s, %s, 'draft')
                ON CONFLICT DO NOTHING
                """,
                (url_id, kit_id, r_contact, r_sub, r_body),
            )

            if kit_id:
                ind_query = """
                    SELECT redacted_display, full_value_encrypted
                    FROM indicators
                    WHERE kit_id = %s AND type IN ('telegram_token', 'telegram_chat')
                """
                telegram_inds = fetch_all(ind_query, (kit_id,))
                for ind in telegram_inds:
                    token = (
                        decrypt_indicator(ind.get("full_value_encrypted"))
                        or ind["redacted_display"]
                    )
                    t_sub, t_body = telegram_report(token, kit_sha)
                    execute(
                        """
                        INSERT INTO takedowns (url_id, kit_id, target_type, contact, subject, body, status)
                        VALUES (%s, %s, 'telegram', 'abuse@telegram.org', %s, %s, 'draft')
                        """,
                        (url_id, kit_id, t_sub, t_body),
                    )

            log.info(
                "takedown_draft_created",
                url_id=url_id,
                host=host,
                has_kit=kit_id is not None,
                abuse_email=h_contact,
            )

        except Exception as e:
            log.exception(
                "Error generating draft takedowns for URL ID %s: %s", url_row.get("id"), e
            )

    return processed_count
