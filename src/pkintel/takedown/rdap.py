"""Abuse-contact resolution via RDAP (with a python-whois fallback).

Given a phishing *hostname* we resolve its IP, query RDAP for the IP and the
registrable domain (``https://rdap.org/ip/<ip>`` and
``https://rdap.org/domain/<domain>``) and extract the responsible **abuse
email**, **registrar** and **ASN**. Everything network-facing goes through the
polite, per-host-throttled client in :mod:`pkintel.http`; the JSON parsing is
done by small pure helpers (``parse_rdap_abuse`` etc.) that are unit-tested
without a network.

Nothing here ever contacts attacker infrastructure — RDAP registries and DNS
only. See ``docs/SCOPE_AND_ETHICS.md``.
"""

from __future__ import annotations

import re
import socket
from typing import Any

import httpx

from pkintel.db import execute, record_audit
from pkintel.http import polite_client, polite_get
from pkintel.logging import get_logger

log = get_logger(__name__)

# A short, deliberately non-exhaustive list of multi-label public suffixes so we
# can derive a registrable domain from a hostname without pulling a full Public
# Suffix List. UAE-first, plus the common ones we actually meet.
_MULTI_LABEL_TLDS = frozenset(
    {
        "co.ae", "gov.ae", "ac.ae", "org.ae", "net.ae", "sch.ae", "mil.ae",
        "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk",
        "com.au", "net.au", "org.au", "gov.au",
        "co.nz", "co.za", "com.br", "com.sg", "com.my", "com.tr", "com.mx",
        "co.in", "co.jp", "co.kr", "com.cn", "com.hk",
    }
)

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


# ---------------------------------------------------------------------------
# Pure helpers (no I/O — unit tested directly)
# ---------------------------------------------------------------------------
def registrable_domain(host: str | None) -> str | None:
    """Best-effort registrable domain for ``host``.

    Returns ``None`` for empty input or IP literals (which have no domain
    registration). Uses a small multi-label-TLD table so ``login.bank.co.ae``
    collapses to ``bank.co.ae`` rather than the unregistrable ``co.ae``.
    """
    if not host:
        return None
    host = host.strip().lower().rstrip(".")
    host = re.sub(r":\d+$", "", host)  # strip a trailing :port
    if not host or _IPV4_RE.match(host) or ":" in host:
        return None  # IPv4/IPv6 literal — no registrable domain
    labels = [part for part in host.split(".") if part]
    if len(labels) < 2:
        return None
    if ".".join(labels[-2:]) in _MULTI_LABEL_TLDS and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _vcard_email(entity: dict[str, Any]) -> str | None:
    """Extract the first email from an RDAP entity's jCard (vcardArray)."""
    vcard = entity.get("vcardArray")
    if not (isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list)):
        return None
    for item in vcard[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == "email":
            value = item[3]
            if isinstance(value, str) and "@" in value:
                return value.strip()
    return None


def _vcard_field(entity: dict[str, Any], field: str) -> str | None:
    """Extract a scalar jCard field (e.g. ``fn``) from an RDAP entity."""
    vcard = entity.get("vcardArray")
    if not (isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list)):
        return None
    for item in vcard[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == field:
            value = item[3]
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def _iter_entities(node: Any):
    """Yield every entity object in an RDAP response, recursing into nested
    ``entities`` arrays (abuse contacts are frequently nested one level down)."""
    if not isinstance(node, dict):
        return
    entities = node.get("entities")
    if not isinstance(entities, list):
        return
    for ent in entities:
        if isinstance(ent, dict):
            yield ent
            yield from _iter_entities(ent)


def parse_rdap_abuse(data: Any) -> str | None:
    """Return the abuse-contact email from an RDAP response, or ``None``.

    Prefers an entity whose ``roles`` include ``"abuse"``; otherwise falls back
    to technical/administrative/registrar contacts and finally to any entity
    email. Purely functional — feed it ``response.json()``.
    """
    if not isinstance(data, dict):
        return None
    fallback: list[tuple[list[str], str]] = []
    for ent in _iter_entities(data):
        roles = ent.get("roles") or []
        roles = [r for r in roles if isinstance(r, str)]
        email = _vcard_email(ent)
        if not email:
            continue
        if "abuse" in roles:
            return email
        fallback.append((roles, email))
    for wanted in ("technical", "administrative", "registrar", "registrant"):
        for roles, email in fallback:
            if wanted in roles:
                return email
    return fallback[0][1] if fallback else None


def parse_rdap_registrar(data: Any) -> str | None:
    """Return the registrar name from a domain RDAP response, or ``None``."""
    if not isinstance(data, dict):
        return None
    for ent in _iter_entities(data):
        roles = ent.get("roles") or []
        if isinstance(roles, list) and "registrar" in roles:
            name = _vcard_field(ent, "fn")
            if name:
                return name
    return None


def parse_rdap_asn(data: Any) -> tuple[int | None, str | None]:
    """Best-effort (ASN, network/ASN name) from an IP RDAP response.

    RDAP does not standardise origin-ASN on IP objects, so we look at the common
    RIR extensions and the network ``name`` and degrade gracefully to
    ``(None, name)``.
    """
    if not isinstance(data, dict):
        return None, None
    name = data.get("name") if isinstance(data.get("name"), str) else None
    # ARIN extension: array of origin AS numbers.
    origins = data.get("arin_originas0_originautnums")
    if isinstance(origins, list) and origins:
        try:
            return int(origins[0]), name
        except (TypeError, ValueError):
            pass
    # autnum object (rdap.org/autnum/<n>): handle like "AS15169" or startAutnum.
    handle = data.get("handle")
    if isinstance(handle, str) and handle.upper().startswith("AS") and handle[2:].isdigit():
        return int(handle[2:]), name
    start = data.get("startAutnum")
    if isinstance(start, int):
        return start, name
    return None, name


def _pick_abuse_email(emails: Any) -> str | None:
    """From a whois email or list of emails, prefer an ``abuse@`` address."""
    if isinstance(emails, str):
        return emails.strip() or None
    if isinstance(emails, (list, tuple)):
        cleaned = [e.strip() for e in emails if isinstance(e, str) and "@" in e]
        for e in cleaned:
            if "abuse" in e.lower():
                return e
        return cleaned[0] if cleaned else None
    return None


# ---------------------------------------------------------------------------
# I/O
# ---------------------------------------------------------------------------
def _resolve_ip(host: str) -> str | None:
    """Resolve ``host`` to an IPv4 address via DNS (passive lookup)."""
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, OSError) as exc:
        log.debug("dns_resolve_failed", host=host, error=str(exc))
        return None


def _rdap_get(client: httpx.Client, url: str) -> dict[str, Any] | None:
    """GET an RDAP document politely; return parsed JSON or ``None``."""
    try:
        resp = polite_get(client, url, headers={"Accept": "application/rdap+json"})
    except httpx.HTTPError as exc:
        log.debug("rdap_fetch_failed", url=url, error=str(exc))
        return None
    if resp.status_code != 200:
        log.debug("rdap_non_200", url=url, status=resp.status_code)
        return None
    try:
        data = resp.json()
    except ValueError as exc:
        log.debug("rdap_bad_json", url=url, error=str(exc))
        return None
    return data if isinstance(data, dict) else None


def _whois_fallback(host: str, result: dict[str, Any]) -> None:
    """Fill gaps in ``result`` using python-whois. Best-effort, never raises."""
    try:
        import whois  # python-whois

        record = whois.whois(host)
    except Exception as exc:  # noqa: BLE001 - whois is flaky; degrade gracefully
        log.debug("whois_failed", host=host, error=str(exc))
        return
    if not result.get("abuse_email"):
        result["abuse_email"] = _pick_abuse_email(getattr(record, "emails", None))
    if not result.get("registrar"):
        registrar = getattr(record, "registrar", None)
        if isinstance(registrar, str) and registrar.strip():
            result["registrar"] = registrar.strip()
    if not result.get("country"):
        country = getattr(record, "country", None)
        if isinstance(country, str) and country.strip():
            result["country"] = country.strip()


def resolve_abuse(host: str) -> dict[str, Any]:
    """Resolve the abuse contact / registrar / ASN for a hostname.

    Returns a dict with keys ``ip, abuse_email, registrar, asn, asn_name,
    country`` (values may be ``None``). Queries RDAP for the IP and the
    registrable domain, then falls back to whois for anything still missing.
    """
    result: dict[str, Any] = {
        "ip": None,
        "abuse_email": None,
        "registrar": None,
        "asn": None,
        "asn_name": None,
        "country": None,
    }
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return result

    result["ip"] = _resolve_ip(host)
    client = polite_client()
    try:
        if result["ip"]:
            ip_data = _rdap_get(client, f"https://rdap.org/ip/{result['ip']}")
            if ip_data:
                result["abuse_email"] = parse_rdap_abuse(ip_data)
                asn, asn_name = parse_rdap_asn(ip_data)
                result["asn"] = asn
                result["asn_name"] = asn_name
                country = ip_data.get("country")
                if isinstance(country, str):
                    result["country"] = country

        domain = registrable_domain(host)
        if domain:
            dom_data = _rdap_get(client, f"https://rdap.org/domain/{domain}")
            if dom_data:
                result["registrar"] = parse_rdap_registrar(dom_data)
                if not result["abuse_email"]:
                    result["abuse_email"] = parse_rdap_abuse(dom_data)
    finally:
        client.close()

    if not result["abuse_email"] or not result["registrar"]:
        _whois_fallback(host, result)

    return result


def enrich_host(host: str) -> dict[str, Any]:
    """Resolve abuse info for ``host`` and upsert the ``hosts`` row.

    Returns the resolved info dict (as :func:`resolve_abuse`). The abuse email
    stored here is a *registry/registrar* contact (e.g. ``abuse@cloudflare.com``)
    — never a victim address.
    """
    info = resolve_abuse(host)
    _upsert_host(host, info)
    record_audit(
        "takedown.rdap",
        "enrich",
        host,
        ip=info.get("ip"),
        asn=info.get("asn"),
        registrar=info.get("registrar"),
        abuse_email_present=bool(info.get("abuse_email")),
    )
    return info


def _upsert_host(host: str, info: dict[str, Any]) -> None:
    """Insert or update the ``hosts`` enrichment row (COALESCE keeps old data)."""
    execute(
        """
        INSERT INTO hosts
            (hostname, ip, asn, asn_name, country, registrar, rdap_abuse_email, enriched_at)
        VALUES
            (%(hostname)s, %(ip)s, %(asn)s, %(asn_name)s, %(country)s,
             %(registrar)s, %(abuse_email)s, now())
        ON CONFLICT (hostname) DO UPDATE SET
            ip               = COALESCE(EXCLUDED.ip, hosts.ip),
            asn              = COALESCE(EXCLUDED.asn, hosts.asn),
            asn_name         = COALESCE(EXCLUDED.asn_name, hosts.asn_name),
            country          = COALESCE(EXCLUDED.country, hosts.country),
            registrar        = COALESCE(EXCLUDED.registrar, hosts.registrar),
            rdap_abuse_email = COALESCE(EXCLUDED.rdap_abuse_email, hosts.rdap_abuse_email),
            enriched_at      = now()
        """,
        {
            "hostname": host,
            "ip": info.get("ip"),
            "asn": info.get("asn"),
            "asn_name": info.get("asn_name"),
            "country": info.get("country"),
            "registrar": info.get("registrar"),
            "abuse_email": info.get("abuse_email"),
        },
    )
