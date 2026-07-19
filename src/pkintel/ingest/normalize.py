"""URL canonicalisation, hashing, and host extraction — pure functions.

These functions are the single source of truth for turning a messy feed URL
into (a) a stable canonical string, (b) its ``url_hash`` (the UNIQUE dedupe key
in the ``urls`` table), and (c) its host. They perform no I/O and are safe to
unit test in isolation.

Canonicalisation rules (deliberately conservative — we must not collapse two
*genuinely different* phishing URLs into one, nor split one into two):

  * lowercase the scheme and the host;
  * add an ``http://`` scheme if the raw value has none (bare domains appear in
    community lists);
  * strip the default port (80 for http, 443 for https);
  * drop the URL fragment (``#...``);
  * keep the path and query verbatim (they often carry the phishing token);
  * drop a lone trailing ``/`` on a bare host (``http://x/`` -> ``http://x``).
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from pkintel.redact import sha256_hex

_DEFAULT_PORTS = {"http": "80", "https": "443"}


def _split_netloc(netloc: str) -> tuple[str, str, str]:
    """Split a netloc into ``(userinfo, host, port)`` without lowercasing.

    Handles optional ``user:pass@`` credentials and bracketed IPv6 literals
    such as ``[2001:db8::1]:8443``.
    """
    userinfo = ""
    hostport = netloc
    if "@" in netloc:
        userinfo, hostport = netloc.rsplit("@", 1)

    host = hostport
    port = ""
    if hostport.startswith("["):  # IPv6 literal: [::1] or [::1]:443
        end = hostport.find("]")
        if end != -1:
            host = hostport[: end + 1]
            rest = hostport[end + 1 :]
            if rest.startswith(":"):
                port = rest[1:]
    elif ":" in hostport:
        host, port = hostport.rsplit(":", 1)
    return userinfo, host, port


def canonical_url(raw: str) -> str:
    """Return the canonical form of ``raw``.

    Raises ``ValueError`` if the input is empty or has no host. Idempotent:
    ``canonical_url(canonical_url(x)) == canonical_url(x)``.
    """
    if raw is None:
        raise ValueError("empty url")
    s = raw.strip()
    if not s:
        raise ValueError("empty url")

    if "://" not in s:
        s = "http://" + s

    parts = urlsplit(s)
    scheme = parts.scheme.lower()
    userinfo, host, port = _split_netloc(parts.netloc)
    host = host.lower().rstrip(".")
    if not host:
        raise ValueError(f"no host in url: {raw!r}")

    if port and port == _DEFAULT_PORTS.get(scheme):
        port = ""

    netloc = host
    if port:
        netloc = f"{host}:{port}"
    if userinfo:
        netloc = f"{userinfo}@{netloc}"

    path = parts.path
    query = parts.query
    # Drop a lone trailing slash on a bare host, but keep it on real paths.
    if path == "/" and not query:
        path = ""

    # Fragment is intentionally dropped (last element -> "").
    return urlunsplit((scheme, netloc, path, query, ""))


def url_hash(canonical: str) -> str:
    """SHA-256 hex of a canonical URL string (the ``urls.url_hash`` key)."""
    return sha256_hex(canonical)


def host_of(url: str) -> str:
    """Return the lowercased host of ``url`` (no port, no credentials).

    Accepts raw or canonical input; returns ``""`` only for genuinely
    host-less values (callers treat that as "skip").
    """
    s = (url or "").strip()
    if not s:
        return ""
    if "://" not in s:
        s = "http://" + s
    _, host, _ = _split_netloc(urlsplit(s).netloc)
    return host.lower().rstrip(".")
