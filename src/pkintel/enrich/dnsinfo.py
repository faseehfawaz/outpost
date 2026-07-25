"""DNS resolution and ASN mapping.

DNS is the only enrichment step that involves **no contact with the target at
all** — we ask a resolver, never the phishing host. It is therefore both the
cheapest and the least intrusive signal we have, and it yields the ``shared_ip``
pivot edge (weight 0.7).

ASN lookup uses Team Cymru's DNS-based IP-to-ASN service. That choice is
deliberate:

* no API key, no account, no rate-limit negotiation;
* it is a plain DNS query, so it inherits the resolver caching we already have;
* it is the long-standing standard method, designed for exactly this use.

The alternative — RDAP per IP — is far slower, more heavily rate-limited, and
would put us in a position of hammering registry infrastructure at pipeline
volume.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pkintel.logging import get_logger

log = get_logger(__name__)

_DEFAULT_TIMEOUT_S = 5.0

# Team Cymru IP-to-ASN, DNS interface.
#   origin:  <reversed-octets>.origin.asn.cymru.com  TXT
#            -> "13335 | 104.16.0.0/12 | US | arin | 2010-07-14"
#   asn:     AS<n>.asn.cymru.com TXT
#            -> "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
_CYMRU_ORIGIN_SUFFIX = "origin.asn.cymru.com"
_CYMRU_ASN_SUFFIX = "asn.cymru.com"


@dataclass
class DnsInfo:
    """Resolution results for one hostname."""

    ips: list[str] = field(default_factory=list)
    nameservers: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return bool(self.ips)


@dataclass
class AsnInfo:
    """ASN mapping for one IP."""

    asn: int | None = None
    asn_name: str | None = None
    country: str | None = None
    prefix: str | None = None


# --------------------------------------------------------------------------- pure parsers
def parse_cymru_origin(txt: str) -> AsnInfo:
    """Parse an ``origin.asn.cymru.com`` TXT record. Pure.

    Example input::

        13335 | 104.16.0.0/12 | US | arin | 2010-07-14

    An IP announced by several ASNs returns multiple space-separated ASNs in
    field 0 (``"13335 20940"``); we take the first, which is the origin AS.
    """
    info = AsnInfo()
    if not txt:
        return info
    parts = [p.strip() for p in txt.strip().strip('"').split("|")]
    if not parts or not parts[0]:
        return info

    first_asn = parts[0].split()[0] if parts[0].split() else ""
    try:
        info.asn = int(first_asn)
    except ValueError:
        return info

    if len(parts) > 1 and parts[1]:
        info.prefix = parts[1]
    if len(parts) > 2 and parts[2]:
        info.country = parts[2]
    return info


def parse_cymru_asname(txt: str) -> str | None:
    """Parse an ``AS<n>.asn.cymru.com`` TXT record into a network name. Pure.

    Example input::

        13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US

    The name is the last field. The trailing ``", US"`` country suffix is kept —
    it is part of how Cymru names networks and is useful context.
    """
    if not txt:
        return None
    parts = [p.strip() for p in txt.strip().strip('"').split("|")]
    if len(parts) < 5:
        return None
    return parts[4] or None


def reverse_octets(ip: str) -> str | None:
    """Reverse an IPv4 address for the Cymru origin query. Pure.

    ``104.21.5.7`` -> ``7.5.21.104``. Returns ``None`` for anything that is not
    a plain IPv4 address (Cymru's IPv6 interface uses a different encoding we do
    not currently need).
    """
    if not ip:
        return None
    parts = ip.strip().split(".")
    if len(parts) != 4:
        return None
    for p in parts:
        if not p.isdigit() or not 0 <= int(p) <= 255:
            return None
    return ".".join(reversed(parts))


# --------------------------------------------------------------------------- I/O
def dnspython_available() -> bool:
    """True if dnspython is importable.

    Checked via ``find_spec`` rather than a bare ``import dns.resolver`` in a
    try/except: the bare import looks like dead code to linters (it is only
    executed for its side effect of raising) and was flagged as such.
    """
    from importlib.util import find_spec

    return find_spec("dns.resolver") is not None


def _resolver(timeout_s: float):
    import dns.resolver

    res = dns.resolver.Resolver()
    res.timeout = timeout_s
    res.lifetime = timeout_s
    return res


def resolve_host(hostname: str, timeout_s: float = _DEFAULT_TIMEOUT_S) -> DnsInfo:
    """Resolve ``hostname`` to its A records and authoritative nameservers.

    All A records are kept, not just the first: fast-flux and round-robin
    campaigns are invisible if we only record one address.
    """
    info = DnsInfo()
    if not hostname:
        info.error = "empty_hostname"
        return info

    if not dnspython_available():
        info.error = "dnspython_not_installed"
        return info

    res = _resolver(timeout_s)

    try:
        answers = res.resolve(hostname, "A")
        info.ips = sorted({str(r) for r in answers})
    except Exception as exc:  # noqa: BLE001 - NXDOMAIN is a normal, informative outcome
        info.error = f"{type(exc).__name__}"

    # Nameservers are a weaker but real pivot: campaigns often share a bespoke
    # NS. Failure here is non-fatal; A records are what matter.
    try:
        ns_answers = res.resolve(hostname, "NS")
        info.nameservers = sorted({str(r).rstrip(".").lower() for r in ns_answers})
    except Exception:  # noqa: BLE001, S110 - most hostnames are not zone apexes
        pass

    return info


def lookup_asn(ip: str, timeout_s: float = _DEFAULT_TIMEOUT_S) -> AsnInfo:
    """Map ``ip`` to its origin ASN via Team Cymru. Never raises."""
    info = AsnInfo()
    rev = reverse_octets(ip)
    if not rev or not dnspython_available():
        return info

    res = _resolver(timeout_s)

    try:
        answers = res.resolve(f"{rev}.{_CYMRU_ORIGIN_SUFFIX}", "TXT")
        txt = "".join(s.decode() if isinstance(s, bytes) else str(s) for s in answers[0].strings)
        info = parse_cymru_origin(txt)
    except Exception as exc:  # noqa: BLE001
        log.debug("cymru_origin_failed", ip=ip, error=str(exc))
        return info

    if info.asn is None:
        return info

    try:
        answers = res.resolve(f"AS{info.asn}.{_CYMRU_ASN_SUFFIX}", "TXT")
        txt = "".join(s.decode() if isinstance(s, bytes) else str(s) for s in answers[0].strings)
        info.asn_name = parse_cymru_asname(txt)
    except Exception as exc:  # noqa: BLE001 - the ASN number alone is still useful
        log.debug("cymru_asname_failed", asn=info.asn, error=str(exc))

    return info
