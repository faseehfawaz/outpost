"""
Analyzer runner to orchestrate extracting and inspecting phishing kits.
"""

import tempfile
import traceback
from pathlib import Path

from pkintel.analyzer.deobfuscate import deobfuscate
from pkintel.analyzer.indicators import extract_indicators
from pkintel.analyzer.inventory import process_inventory
from pkintel.analyzer.safe_extract import extract_archive
from pkintel.config import settings
from pkintel.db import claim_rows, connection, execute
from pkintel.logging import get_logger
from pkintel.storage import get_storage

log = get_logger(__name__)


def run_once(worker_id: str = "analyze-1", limit: int = 5) -> int:
    """Claim and analyze stored kits."""
    kits = claim_rows(
        "kits",
        ready_col="analysis_state",
        ready_value="stored",
        busy_value="analyzing",
        worker_id=worker_id,
        limit=limit,
    )

    if not kits:
        return 0

    storage = get_storage()
    processed = 0

    for kit in kits:
        kit_id = kit["id"]
        stored_key = kit["stored_key"]

        try:
            log.info(f"Analyzing kit {kit_id} ({stored_key})")
            archive_bytes = storage.get(stored_key)
            if not archive_bytes:
                raise ValueError(f"Archive not found in storage: {stored_key}")

            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                archive_path = temp_path / "archive.zip"
                archive_path.write_bytes(archive_bytes)

                # Safe extract
                dest_dir = temp_path / "extracted"
                dest_dir.mkdir()

                extracted_files = extract_archive(
                    archive_path,
                    dest_dir,
                    max_files=settings.analyzer_max_files,
                    max_uncompressed_bytes=settings.analyzer_max_uncompressed_bytes,
                )

                # Inventory
                inventory, fingerprint = process_inventory(extracted_files, dest_dir)

                # Indicators & Deobfuscation
                all_indicators = []
                for file_path in extracted_files:
                    if file_path.suffix.lower() == ".php":
                        text = file_path.read_text(errors="ignore")
                        deobf_text = deobfuscate(
                            text, max_rounds=settings.analyzer_max_deobf_rounds
                        )

                        rel_path = str(file_path.relative_to(dest_dir))
                        file_inds = extract_indicators(deobf_text, rel_path)
                        all_indicators.extend(file_inds)

                # Update DB
                with connection() as conn:
                    with conn.transaction():
                        # Update kit
                        execute(
                            conn,
                            "UPDATE kits SET analysis_state = 'analyzed', analyzed_at = now() WHERE id = %s",
                            (kit_id,),
                        )

                        # Insert files
                        for inv_file in inventory:
                            execute(
                                conn,
                                "INSERT INTO kit_files (kit_id, path, sha256, tlsh, normalized_token_hash, size, mime, is_obfuscated) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING",
                                (
                                    kit_id,
                                    inv_file.path,
                                    inv_file.sha256,
                                    inv_file.tlsh,
                                    inv_file.normalized_token_hash,
                                    inv_file.size,
                                    inv_file.mime,
                                    inv_file.is_obfuscated,
                                ),
                            )

                        # Insert indicators
                        for ind in all_indicators:
                            execute(
                                conn,
                                "INSERT INTO indicators (kit_id, type, value_hash, redacted_display, full_value_encrypted, confidence, found_in_path, meta) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING",
                                (
                                    kit_id,
                                    ind.type.value,
                                    ind.value_hash,
                                    ind.redacted_display,
                                    ind.full_value_encrypted,
                                    ind.confidence,
                                    ind.found_in_path,
                                    "{}",
                                ),  # Serialize meta properly in real app
                            )

                        # Insert fingerprint
                        execute(
                            conn,
                            "INSERT INTO fingerprints (kit_id, fileset_hash, antibot_hash, token_hash, author_strings, file_sha_set) VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING",
                            (
                                kit_id,
                                fingerprint.fileset_hash,
                                fingerprint.antibot_hash,
                                fingerprint.token_hash,
                                fingerprint.author_strings,
                                fingerprint.file_sha_set,
                            ),
                        )

            processed += 1

        except Exception as e:
            log.error(f"Error analyzing kit {kit_id}: {e}")
            error_msg = traceback.format_exc()
            with connection() as conn:
                execute(
                    conn,
                    "UPDATE kits SET analysis_state = 'error', analysis_error = %s WHERE id = %s",
                    (error_msg, kit_id),
                )

    return processed
