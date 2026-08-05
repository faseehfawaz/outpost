"""Entrypoint for the analyzer sandbox container.

Launched per-kit by :mod:`pkintel.analyzer.runner` inside a container with
``--network none``, ``--read-only``, ``--cap-drop ALL``, ``no-new-privileges``
and memory / CPU / pids / wall-clock bounds. Everything this module touches is
attacker-authored, so it runs here and nowhere else.

Protocol (kept deliberately dumb — one argument in, one document out):

    argv[1]   path to an archive, mounted read-only at /in/archive.zip
    stdout    exactly one AnalysisResult JSON document, nothing else
    stderr    diagnostics — safe to log
    exit 0    success

**stdout carries unredacted indicator values** (``Indicator.full_value``) so the
host can encrypt them at rest. The host must therefore never log stdout. stderr
is the safe channel and is where every diagnostic below goes.
"""

import sys
import tempfile
import traceback
from pathlib import Path

from pkintel.analyzer.deobfuscate import deobfuscate
from pkintel.analyzer.indicators import extract_indicators
from pkintel.analyzer.inventory import process_inventory
from pkintel.analyzer.safe_extract import extract_archive
from pkintel.config import settings
from pkintel.models import AnalysisResult


def analyze_zip(archive_path: Path) -> AnalysisResult:
    """Analyze a single zip file and return an AnalysisResult."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        dest_dir = temp_path / "extracted"
        dest_dir.mkdir()

        # 1. Safe extraction
        extracted_files = extract_archive(
            archive_path,
            dest_dir,
            max_files=settings.analyzer_max_files,
            max_uncompressed_bytes=settings.analyzer_max_uncompressed_bytes,
        )

        # 2. Inventory and Fingerprinting
        inventory, fingerprint = process_inventory(extracted_files, dest_dir)

        # 3. Indicator extraction and Deobfuscation
        all_indicators = []
        victim_log_paths = []

        for file_path in extracted_files:
            name_lower = file_path.name.lower()
            if name_lower in (
                "log.txt",
                "logs.txt",
                "rezult.txt",
                "result.txt",
                "results.txt",
                "data.txt",
            ):
                victim_log_paths.append(str(file_path.relative_to(dest_dir)))

            if file_path.suffix.lower() == ".php":
                text = file_path.read_text(errors="ignore")
                deobf_text = deobfuscate(text, max_rounds=settings.analyzer_max_deobf_rounds)

                rel_path = str(file_path.relative_to(dest_dir))
                file_inds = extract_indicators(deobf_text, rel_path)
                all_indicators.extend(file_inds)

        return AnalysisResult(
            ok=True,
            file_count=len(extracted_files),
            files=inventory,
            indicators=all_indicators,
            fingerprint=fingerprint,
            victim_log_paths=victim_log_paths,
        )


def main():
    """CLI entrypoint."""
    if len(sys.argv) < 2:
        print("Usage: python -m pkintel.analyzer.container_main <archive_path>", file=sys.stderr)
        sys.exit(1)

    archive_path = Path(sys.argv[1])
    if not archive_path.exists():
        err_res = AnalysisResult(ok=False, error=f"Archive not found: {archive_path}")
        print(err_res.model_dump_json())
        sys.exit(1)

    try:
        result = analyze_zip(archive_path)
        print(result.model_dump_json())
    except Exception as e:
        error_msg = f"{e}\n{traceback.format_exc()}"
        err_res = AnalysisResult(ok=False, error=error_msg)
        print(err_res.model_dump_json())
        sys.exit(1)


if __name__ == "__main__":
    main()
