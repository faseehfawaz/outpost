"""
Runner for the phishing-kit hunting pipeline.
"""

from pkintel.db import claim_rows, execute, record_audit
from pkintel.kithunter.collect import hunt
from pkintel.logging import get_logger

log = get_logger(__name__)


def run_once(worker_id: str = "kithunt-1", limit: int = 10) -> int:
    """
    Run the kit hunter worker once.

    Claims URLs with kithunt_state='pending', filters for those that are
    confirmed phish and triaged, then executes the collection logic.
    """
    # Claim rows that are pending
    urls = claim_rows("urls", "kithunt_state", "pending", "hunting", worker_id, limit)
    if not urls:
        return 0

    processed_count = 0
    for url_row in urls:
        url_id = url_row["id"]

        # We only hunt URLs that are confirmed phish and have been triaged
        if not url_row.get("is_phish") or url_row.get("triage_state") != "triaged":
            execute(
                "UPDATE urls SET kithunt_state = 'skipped', kithunt_at = now() WHERE id = %s",
                (url_id,),
            )
            continue

        try:
            # Execute hunt
            result = hunt(url_row)

            # Determine new state based on results
            new_state = "collected" if result.collected else "none"
            attempts = url_row.get("kithunt_attempts", 0) + 1

            # Update url record
            execute(
                """
                UPDATE urls 
                SET kithunt_state = %s, 
                    kithunt_attempts = %s, 
                    kithunt_at = now() 
                WHERE id = %s
                """,
                (new_state, attempts, url_id),
            )

            # Record audit
            audit_meta = {
                "url_id": url_id,
                "collected": result.collected,
                "kit_sha256": getattr(result, "kit_sha256", None),
            }
            record_audit("kithunt_complete", audit_meta)

            processed_count += 1

        except Exception as e:
            log.exception("Error during kit hunt for URL ID %s: %s", url_id, e)
            execute(
                "UPDATE urls SET kithunt_state = 'error', kithunt_at = now() WHERE id = %s",
                (url_id,),
            )
            record_audit("kithunt_error", {"url_id": url_id, "error": str(e)})

    return processed_count
