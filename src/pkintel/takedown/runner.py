"""
Runner for the takedown pipeline.

Phase 1: Generates draft takedown abuse reports for confirmed phish URLs.
         Works with or without a collected kit — URL-based takedowns are
         generated for every phishing URL that does not yet have a takedown.
Phase 2: Sends draft takedowns (respecting dry-run settings).
"""

from pkintel.config import settings
from pkintel.db import claim_rows, execute, fetch_all, record_audit
from pkintel.logging import get_logger
from pkintel.takedown.rdap import enrich_host
from pkintel.takedown.templates import host_abuse_report, registrar_report, telegram_report

log = get_logger(__name__)


def run_once(worker_id: str = "takedown-1", limit: int = 50) -> int:
    """
    Run the takedown worker once.

    Phase 1: Generates draft takedowns for phish URLs (kit optional).
    Phase 2: Sends draft takedowns (respecting dry-run settings).
    """
    processed_count = 0

    # --- Phase 1: Generate Drafts ---
    # Fetch phish URLs that don't have takedowns associated yet.
    # This now works for ALL confirmed phish — not just those with kits.
    query_drafts = """
        SELECT u.id, u.url, u.host
        FROM urls u
        LEFT JOIN takedowns t ON u.id = t.url_id
        WHERE u.is_phish = true AND t.id IS NULL
        LIMIT %s
    """
    urls_to_draft = fetch_all(query_drafts, (limit,))

    for url_row in urls_to_draft:
        try:
            url_id = url_row["id"]
            url = url_row["url"]
            host = url_row["host"]

            # Enrich host via RDAP/WHOIS
            host_info = enrich_host(host)

            # Check if this URL has an associated kit (optional)
            kit_query = """
                SELECT k.id, k.sha256 
                FROM kits k 
                WHERE k.id = (SELECT kit_id FROM urls WHERE id = %s LIMIT 1)
            """
            kits = fetch_all(kit_query, (url_id,))
            kit_id = kits[0]["id"] if kits else None
            kit_sha = kits[0]["sha256"] if kits else None
            kit_summary = {"sha256": kit_sha, "count": 1 if kit_id else 0}

            # 1. Host Abuse Report — always generated
            h_sub, h_body = host_abuse_report(url, host_info, kit_summary)
            h_contact = host_info.get("abuse_email", "abuse@localhost")
            execute(
                """
                INSERT INTO takedowns (url_id, kit_id, target_type, contact, subject, body, status)
                VALUES (%s, %s, 'host', %s, %s, %s, 'draft')
                """,
                (url_id, kit_id, h_contact, h_sub, h_body),
            )

            # 2. Registrar Abuse Report — always generated
            r_sub, r_body = registrar_report(url, host_info, kit_summary)
            r_contact = host_info.get("registrar_abuse_email", "abuse@localhost")
            execute(
                """
                INSERT INTO takedowns (url_id, kit_id, target_type, contact, subject, body, status)
                VALUES (%s, %s, 'registrar', %s, %s, %s, 'draft')
                """,
                (url_id, kit_id, r_contact, r_sub, r_body),
            )

            # 3. Telegram Report (only if kit has Telegram indicators)
            if kit_id:
                ind_query = "SELECT value FROM indicators WHERE kit_id = %s AND type = 'telegram'"
                telegram_inds = fetch_all(ind_query, (kit_id,))
                for ind in telegram_inds:
                    t_sub, t_body = telegram_report(ind["value"], kit_sha)
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

    # --- Phase 2: Send Drafts ---
    drafts = claim_rows(
        "takedowns",
        ready_col="status",
        ready_value="draft",
        busy_value="sending",
        worker_id=worker_id,
        limit=limit,
    )
    for draft in drafts:
        draft_id = draft["id"]
        contact = draft.get("contact")

        try:
            if settings.takedown_dry_run:
                log.info("DRY RUN: Sending takedown %s to %s", draft_id, contact)
            else:
                log.info("Sending takedown %s to %s", draft_id, contact)
                # Actual delivery logic goes here (e.g., SMTP)

            execute(
                "UPDATE takedowns SET status = 'sent', sent_at = now() WHERE id = %s", (draft_id,)
            )
            processed_count += 1
            record_audit("takedown_sent", {"takedown_id": draft_id, "contact": contact})

        except Exception as e:
            log.exception("Failed to send takedown %s: %s", draft_id, e)
            execute("UPDATE takedowns SET status = 'error' WHERE id = %s", (draft_id,))

    return processed_count
