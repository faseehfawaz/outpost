"""Host enrichment — resolve, fingerprint and map the infrastructure.

Turns a bare hostname into the facts the pivot graph needs:

    adcb-secure-login.com
        -> A       104.21.x.x, 172.67.x.x
        -> ASN     AS13335 CLOUDFLARENET (US)
        -> TLS     sha256:1f3a..., issuer "R3", SANs [adcb-secure-login.com,
                   adcb-verify.com, adcb-login.net]      <-- the campaign, in one field
        -> NS      ns1.somehost.com, ns2.somehost.com

That SAN list is often the whole campaign in a single lookup: operators
routinely put every lookalike they own onto one certificate.

Everything here is passive: a DNS query (which never touches the target at all)
and a TLS handshake (which is strictly less contact than the HTTP GET triage
already performs — we complete the handshake, read the certificate the server
volunteers to every anonymous client, and disconnect without sending a request).
"""

from __future__ import annotations
