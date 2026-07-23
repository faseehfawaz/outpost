"""
Inventory processing for extracted phishing kits.
"""

import mimetypes
import re
from pathlib import Path

import tlsh

from pkintel.analyzer.deobfuscate import is_obfuscated
from pkintel.models import Fingerprint, InventoryFile
from pkintel.redact import sha256_hex

AUTHOR_RE = re.compile(r"(?i)(?:coded by|created by|author:|by:)\s*([^\r\n]+)")


def normalize_php(text: str) -> str:
    """Normalize PHP file content for token hashing."""
    # Remove comments (single line and multi-line)
    text = re.sub(r"//.*", "", text)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"#.*", "", text)
    # Strip whitespace
    text = re.sub(r"\s+", "", text)
    # Strip variable names (naive replacement to $VAR)
    text = re.sub(r"\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*", "$VAR", text)
    return text


def process_inventory(files: list[Path], base_dir: Path) -> tuple[list[InventoryFile], Fingerprint]:
    """Analyze files to create inventory and kit fingerprint."""
    inventory = []
    author_strings = set()
    file_sha_set = set()

    # For anti-bot detection
    bot_ips = []

    # For kit fingerprint
    all_normalized = []

    for file_path in files:
        if not file_path.is_file():
            continue

        try:
            content = file_path.read_bytes()
        except Exception:
            continue

        sha256 = sha256_hex(content)
        file_sha_set.add(sha256)
        size = len(content)
        mime = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"

        t_hash = ""
        if size >= 50:
            t_hash = tlsh.hash(content)

        obfuscated = False
        norm_hash = ""

        # Text-based analysis for PHP files
        if file_path.suffix.lower() == ".php" or "text" in mime:
            try:
                text_content = content.decode("utf-8", errors="ignore")
                obfuscated = is_obfuscated(text_content)

                # Extract author strings
                for match in AUTHOR_RE.finditer(text_content):
                    author_strings.add(match.group(1).strip())

                if file_path.suffix.lower() == ".php":
                    norm_text = normalize_php(text_content)
                    norm_hash = sha256_hex(norm_text.encode("utf-8"))
                    all_normalized.append(norm_text)

            except Exception:
                pass

        rel_path = str(file_path.relative_to(base_dir))
        inventory.append(
            InventoryFile(
                path=rel_path,
                sha256=sha256,
                tlsh=t_hash,
                normalized_token_hash=norm_hash,
                size=size,
                mime=mime,
                is_obfuscated=obfuscated,
            )
        )

    # Compute fingerprint
    fileset_hash = sha256_hex("".join(sorted(file_sha_set)).encode())
    token_hash = sha256_hex("".join(sorted(all_normalized)).encode()) if all_normalized else ""
    antibot_hash = ""  # Placeholder for actual antibot list detection hash

    fingerprint = Fingerprint(
        fileset_hash=fileset_hash,
        antibot_hash=antibot_hash,
        token_hash=token_hash,
        author_strings=list(author_strings),
        file_sha_set=list(file_sha_set),
    )

    return inventory, fingerprint
