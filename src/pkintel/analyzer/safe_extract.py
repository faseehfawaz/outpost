"""Archive extraction with hard safety guards (ZIP-SLIP / TAR-SLIP + zip-bomb).

Phishing kits arrive as attacker-authored archives. Extracting one naively is a
remote-code / file-overwrite primitive: a member named ``../../etc/cron.d/x`` or
``/tmp/evil`` writes outside the destination, and a symlink member can redirect a
later write anywhere on disk. On top of that a small archive can inflate to
gigabytes (a "zip bomb").

This module refuses all of that **before** touching the filesystem:

  * absolute paths and Windows drive paths are rejected;
  * any member whose *resolved* path escapes ``dest_dir`` (``..`` traversal) is
    rejected;
  * symlink / hardlink / device members are rejected (never extracted, never
    followed);
  * a file-count cap and a total-uncompressed-size cap are enforced, and the
    real bytes written are counted during extraction as defence-in-depth against
    a member that lies about its declared size.

Both zip and tar.* are supported. The functions are pure w.r.t. process state —
they only read the archive and write regular files under ``dest_dir``. Nothing
here executes, includes, or follows attacker-controlled content.
"""

from __future__ import annotations

import os
import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath


class UnsafeArchiveError(Exception):
    """Raised when an archive member or the archive as a whole is unsafe.

    Covers zip-slip / tar-slip traversal, absolute paths, symlink/hardlink/device
    members, and the file-count / total-size caps (zip-bomb guard).
    """


# 64 KiB copy buffer — big enough to be efficient, small enough to bound memory.
_COPY_CHUNK = 64 * 1024


def _normalize(name: str) -> str:
    """Return a member name with backslashes normalised to forward slashes."""
    return name.replace("\\", "/")


def _is_absolute(name: str) -> bool:
    return name.startswith("/") or name.startswith("\\") or (len(name) >= 2 and name[1] == ":")


def _escapes(dest_dir: Path, name: str) -> bool:
    """True if ``name`` resolves outside ``dest_dir`` (path traversal)."""
    dest_norm = os.path.normpath(str(dest_dir))
    target = os.path.normpath(os.path.join(dest_norm, name))
    return target != dest_norm and not target.startswith(dest_norm + os.sep)


def _check_name(dest_dir: Path, raw_name: str) -> None:
    """Validate a member path; raise :class:`UnsafeArchiveError` if unsafe."""
    name = _normalize(raw_name)
    if _is_absolute(raw_name):
        raise UnsafeArchiveError(f"absolute path member rejected: {raw_name!r}")
    if ".." in PurePosixPath(name).parts:
        raise UnsafeArchiveError(f"path-traversal member rejected: {raw_name!r}")
    if _escapes(dest_dir, name):
        raise UnsafeArchiveError(f"member escapes destination: {raw_name!r}")


def _zip_is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = info.external_attr >> 16
    return bool(mode) and stat.S_ISLNK(mode)


def _iter_zip(archive_path: str | os.PathLike) -> list[tuple[str, int, bool, bool]]:
    """Yield ``(name, declared_size, is_dir, is_symlink)`` for each zip member."""
    out: list[tuple[str, int, bool, bool]] = []
    with zipfile.ZipFile(archive_path) as zf:
        for info in zf.infolist():
            is_dir = info.is_dir()
            out.append((info.filename, int(info.file_size), is_dir, _zip_is_symlink(info)))
    return out


def _iter_tar(archive_path: str | os.PathLike) -> list[tuple[str, int, bool, bool]]:
    """Yield ``(name, declared_size, is_dir, is_link_or_special)`` for each member."""
    out: list[tuple[str, int, bool, bool]] = []
    with tarfile.open(archive_path) as tf:
        for member in tf.getmembers():
            special = member.issym() or member.islnk() or member.isdev() or member.isfifo()
            out.append((member.name, int(member.size), member.isdir(), special))
    return out


def _archive_kind(archive_path: str | os.PathLike) -> str:
    if zipfile.is_zipfile(archive_path):
        return "zip"
    if tarfile.is_tarfile(archive_path):
        return "tar"
    raise UnsafeArchiveError(f"unsupported / unrecognised archive: {archive_path!r}")


def safe_members(
    archive_path: str | os.PathLike,
    dest_dir: str | os.PathLike,
    max_files: int,
    max_uncompressed_bytes: int,
) -> list[str]:
    """Validate every member and return the names that are safe to extract.

    Raises :class:`UnsafeArchiveError` on the first unsafe member (traversal,
    absolute path, or symlink/hardlink/device) or when the file-count /
    total-uncompressed-size caps are exceeded. Directory members are validated
    but not returned (they are created implicitly during extraction).
    """
    dest = Path(dest_dir)
    kind = _archive_kind(archive_path)
    members = _iter_zip(archive_path) if kind == "zip" else _iter_tar(archive_path)

    names: list[str] = []
    total_bytes = 0
    file_count = 0
    for name, size, is_dir, is_special in members:
        if is_special:
            raise UnsafeArchiveError(f"symlink/hardlink/device member rejected: {name!r}")
        _check_name(dest, name)
        if is_dir:
            continue
        file_count += 1
        if file_count > max_files:
            raise UnsafeArchiveError(
                f"file-count cap exceeded (> {max_files}); refusing archive"
            )
        total_bytes += max(size, 0)
        if total_bytes > max_uncompressed_bytes:
            raise UnsafeArchiveError(
                f"uncompressed-size cap exceeded (> {max_uncompressed_bytes} bytes); "
                "possible zip bomb"
            )
        names.append(name)
    return names


def _copy_capped(src, dst, remaining: int) -> int:
    """Stream ``src`` -> ``dst`` up to ``remaining`` bytes. Returns bytes written.

    Raises :class:`UnsafeArchiveError` if the source produces more than
    ``remaining`` bytes (a member lying about its declared size / zip bomb).
    """
    written = 0
    while True:
        chunk = src.read(_COPY_CHUNK)
        if not chunk:
            break
        written += len(chunk)
        if written > remaining:
            raise UnsafeArchiveError("member exceeded uncompressed-size budget during extraction")
        dst.write(chunk)
    return written


def extract_archive(
    archive_path: str | os.PathLike,
    dest_dir: str | os.PathLike,
    max_files: int,
    max_uncompressed_bytes: int,
) -> list[Path]:
    """Safely extract ``archive_path`` under ``dest_dir``.

    Only members that pass :func:`safe_members` are written, and the true number
    of bytes written is counted so a member that under-reports its size still
    cannot blow the total-size budget. Returns the list of extracted file paths.
    """
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    kind = _archive_kind(archive_path)
    allowed = set(safe_members(archive_path, dest, max_files, max_uncompressed_bytes))

    extracted: list[Path] = []
    budget = max_uncompressed_bytes

    if kind == "zip":
        with zipfile.ZipFile(archive_path) as zf:
            for info in zf.infolist():
                if info.is_dir() or info.filename not in allowed:
                    continue
                target = dest / _normalize(info.filename)
                # Re-check the resolved target as belt-and-braces before writing.
                if _escapes(dest, _normalize(info.filename)):
                    raise UnsafeArchiveError(f"member escapes destination: {info.filename!r}")
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as dst:
                    budget -= _copy_capped(src, dst, budget)
                extracted.append(target)
    else:
        with tarfile.open(archive_path) as tf:
            for member in tf.getmembers():
                if member.isdir() or member.name not in allowed:
                    continue
                if not member.isreg():
                    # anything that isn't a plain regular file is skipped
                    continue
                target = dest / _normalize(member.name)
                if _escapes(dest, _normalize(member.name)):
                    raise UnsafeArchiveError(f"member escapes destination: {member.name!r}")
                target.parent.mkdir(parents=True, exist_ok=True)
                src = tf.extractfile(member)
                if src is None:
                    continue
                with src, open(target, "wb") as dst:
                    budget -= _copy_capped(src, dst, budget)
                extracted.append(target)

    return extracted
