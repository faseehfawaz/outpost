"""Candidate-path generation for the kit hunter — pure, side-effect free.

The hunter is *passive* and *rate-limited* (see ``docs/SCOPE_AND_ETHICS.md`` #5):
it never brute-forces or fuzzes. It only ever tries a **short, fixed** list of
guesses derived deterministically from the phishing URL itself. Everything in
this module is a pure function so it can be reasoned about and unit-tested with
zero network access — the actual fetching (and the hard per-host cap) lives in
:mod:`pkintel.kithunter.collect`.
"""

from __future__ import annotations

from collections.abc import Sequence
from urllib.parse import urlsplit


def walk_up_dirs(url: str) -> list[str]:
    """Return the chain of directory URLs from the deepest folder up to root.

    ``https://host/a/b/login.php`` ->
    ``['https://host/a/b/', 'https://host/a/', 'https://host/']``

    A trailing filename is dropped; already-directory URLs keep their depth.
    The result is de-duplicated and ordered deepest-first (we prefer to look
    right next to the deployed kit before climbing toward the web root).
    """
    parts = urlsplit(url)
    scheme = parts.scheme or "https"
    netloc = parts.netloc
    if not netloc:
        return []

    path = parts.path or "/"
    # Drop a trailing filename (anything after the last '/') so we start from a
    # directory. Query/fragment are irrelevant to directory structure.
    if not path.endswith("/"):
        idx = path.rfind("/")
        path = path[: idx + 1] if idx >= 0 else "/"

    base = f"{scheme}://{netloc}"
    segments = [s for s in path.split("/") if s]

    dirs: list[str] = []
    seen: set[str] = set()
    while True:
        directory = "/" + "/".join(segments) + "/" if segments else "/"
        full = base + directory
        if full not in seen:
            seen.add(full)
            dirs.append(full)
        if not segments:
            break
        segments = segments[:-1]
    return dirs


def archive_candidates(dir_url: str, archive_names: Sequence[str]) -> list[str]:
    """Return a short, fixed list of candidate archive URLs inside ``dir_url``.

    Two deterministic sources, in priority order:

    1. **Directory-name guesses** — attackers frequently zip a folder into a
       same-named archive. For ``/a/b/`` this yields ``b.zip`` then ``a.zip``.
    2. The fixed ``archive_names`` list from settings (``kit.zip`` etc.).

    This intentionally generates NO permutations, no wordlists, no extension
    fuzzing — just these deterministic guesses, de-duplicated and ordered.
    ``dir_url`` is expected to be a directory URL (trailing slash); a missing
    slash is tolerated.
    """
    base = dir_url if dir_url.endswith("/") else dir_url + "/"
    segments = [s for s in urlsplit(base).path.split("/") if s]

    names: list[str] = [f"{seg}.zip" for seg in reversed(segments)]
    names.extend(archive_names)

    out: list[str] = []
    seen: set[str] = set()
    for name in names:
        if name in seen:
            continue
        seen.add(name)
        out.append(base + name)
    return out
