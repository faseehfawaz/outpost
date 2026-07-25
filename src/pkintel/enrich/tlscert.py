"""TLS certificate fingerprinting — the strongest pivot signal available.

Why the certificate matters so much
-----------------------------------
When one operator runs a campaign, they usually obtain certificates in a batch.
That leaves two fingerprints that are very hard to avoid:

1. **A shared certificate.** Free CAs let you put many names on one cert, and
   operators do exactly that. If ``adcb-login.com`` and ``emiratesnbd-verify.com``
   appear as SANs on the *same* certificate, they are the same operator. There is
   no innocent explanation, which is why ``shared_cert`` carries weight 1.0 in
   :mod:`pkintel.fingerprint.pivot`.

2. **The SAN list itself.** A single handshake against one known-bad host can
   hand us the operator's entire domain portfolio, including lookalikes we have
   never seen in any feed. This is the cheapest infrastructure discovery
   available anywhere in the platform.

Ethics
------
We open a TLS connection, complete the handshake, read the certificate the
server presents to *every* anonymous client, and disconnect **without sending an
HTTP request**. That is strictly less interaction than the GET triage already
performs. Certificate validation is deliberately disabled — phishing hosts
routinely have expired or mismatched certs, and we want to fingerprint the cert
that is actually served, not reject it.
"""

from __future__ import annotations

import hashlib
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone

from pkintel.logging import get_logger

log = get_logger(__name__)

# Certificates are small; a hostile server cannot make this large. The timeout
# is what actually protects us, since a tarpit would otherwise hold a worker.
_DEFAULT_TIMEOUT_S = 8.0


@dataclass
class CertInfo:
    """What one TLS handshake revealed. All fields best-effort."""

    sha256: str | None = None
    issuer: str | None = None
    subject: str | None = None
    names: list[str] = field(default_factory=list)
    not_before: datetime | None = None
    not_after: datetime | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.sha256 is not None


def parse_cert_datetime(value: str | None) -> datetime | None:
    """Parse OpenSSL's ``notBefore``/``notAfter`` format. Pure.

    Format is e.g. ``"Jun  1 12:00:00 2026 GMT"``. Always UTC, so we attach
    tzinfo explicitly rather than producing a naive datetime that would compare
    incorrectly against ``now(timezone.utc)`` elsewhere.
    """
    if not value:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def extract_names(cert: dict | None) -> list[str]:
    """Pull every DNS name out of a parsed certificate dict. Pure, de-duplicated.

    Reads both the SAN extension (``subjectAltName``) and the legacy CN in
    ``subject``. Wildcards are unwrapped to their base name so ``*.evil.com``
    and ``evil.com`` collapse to one entry — for pivoting we care about the
    domain, not the wildcard form.
    """
    if not cert:
        return []

    out: list[str] = []

    for typ, value in cert.get("subjectAltName", ()) or ():
        if typ.lower() == "dns" and value:
            out.append(value)

    # Legacy CN, for certs predating universal SAN usage.
    for rdn in cert.get("subject", ()) or ():
        for key, value in rdn:
            if key == "commonName" and value:
                out.append(value)

    seen: set[str] = set()
    names: list[str] = []
    for raw in out:
        name = raw.strip().lower().lstrip("*.").rstrip(".")
        if name and name not in seen:
            seen.add(name)
            names.append(name)
    return names


def format_dn(dn: tuple | None) -> str | None:
    """Flatten a parsed distinguished name into a readable string. Pure."""
    if not dn:
        return None
    parts: list[str] = []
    for rdn in dn:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts) if parts else None


def fetch_cert(
    hostname: str,
    port: int = 443,
    timeout_s: float = _DEFAULT_TIMEOUT_S,
) -> CertInfo:
    """Complete a TLS handshake and fingerprint the presented certificate.

    Never raises — a host that refuses TLS, times out, or serves garbage is a
    normal outcome and is reported via ``CertInfo.error``.
    """
    info = CertInfo()
    if not hostname:
        info.error = "empty_hostname"
        return info

    # Deliberately permissive: we are fingerprinting what is served, not
    # validating trust. Expired/self-signed/mismatched certs are exactly the
    # ones we most want to record.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((hostname, port), timeout=timeout_s) as sock:
            # SNI matters: shared hosting serves a different cert per name, and
            # without it we would fingerprint the default vhost instead.
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
                der = tls.getpeercert(binary_form=True)
                parsed = tls.getpeercert()

        if not der:
            info.error = "no_certificate"
            return info

        # SHA-256 of the DER bytes is the standard certificate fingerprint, and
        # is what makes "same cert" comparable across hosts.
        info.sha256 = hashlib.sha256(der).hexdigest()
        info.names = extract_names(parsed)
        info.issuer = format_dn((parsed or {}).get("issuer"))
        info.subject = format_dn((parsed or {}).get("subject"))
        info.not_before = parse_cert_datetime((parsed or {}).get("notBefore"))
        info.not_after = parse_cert_datetime((parsed or {}).get("notAfter"))

    except TimeoutError:  # socket.timeout is an alias for this since 3.10
        info.error = "timeout"
    except (socket.gaierror, ConnectionRefusedError, OSError) as exc:
        info.error = f"connect_failed:{type(exc).__name__}"
    except ssl.SSLError as exc:
        info.error = f"tls_error:{exc.__class__.__name__}"
    except Exception as exc:  # noqa: BLE001 - never let one host kill the batch
        info.error = str(exc)[:200]

    return info
