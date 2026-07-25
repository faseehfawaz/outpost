"""Authenticated encryption for attacker indicator values (ethics-critical).

Background — the bug this module fixes
--------------------------------------
The ``indicators.full_value_encrypted`` column is documented as "for abuse-desk
reporting only; never surfaced publicly", but until now it was written as::

    ind.full_value.encode("utf-8") if ind.full_value else b""

which had *two* defects:

1. ``pkintel.analyzer.indicators`` constructed ``Indicator(...)`` passing
   ``full_value_encrypted=b""`` — a field that does not exist on the model.
   Pydantic silently dropped it and ``full_value`` stayed ``None``, so the
   column was **always empty**. The abuse-desk evidence path was dead.
2. Had it been populated, it would have been **plaintext** in a column named
   ``_encrypted`` — exactly the failure mode ``docs/SCOPE_AND_ETHICS.md``
   forbids.

Design
------
Fernet (AES-128-CBC + HMAC-SHA256, from ``cryptography``) gives us authenticated
symmetric encryption with a compact, versioned token format. We deliberately do
**not** roll our own construction.

Fail-closed policy
------------------
If no key is configured we refuse to store the value at all (returning ``None``)
rather than silently degrading to plaintext. A missing key must cost us
evidence, never the victim's or the researcher's safety. ``sha256`` linkage in
``value_hash`` is unaffected, so clustering keeps working with no key present.

Key management
--------------
Generate one with::

    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

and set ``PKINTEL_INDICATOR_ENC_KEY``. Key rotation is supported by listing the
old keys after the current one (comma-separated): the first key always encrypts,
any key may decrypt (MultiFernet semantics).
"""

from __future__ import annotations

from functools import lru_cache

from pkintel.config import settings
from pkintel.logging import get_logger

log = get_logger(__name__)

_WARNED = {"no_key": False}


@lru_cache(maxsize=1)
def _cipher():
    """Build the MultiFernet from configured keys, or ``None`` if unconfigured.

    Cached: key parsing and Fernet construction are pure functions of config,
    and this is called once per indicator in hot analyzer loops.
    """
    raw = (settings.indicator_enc_key or "").strip()
    if not raw:
        return None

    try:
        from cryptography.fernet import Fernet, MultiFernet
    except ImportError:  # pragma: no cover - dependency is declared in pyproject
        log.error("indicator_encryption_unavailable", reason="cryptography not installed")
        return None

    keys = [k.strip() for k in raw.split(",") if k.strip()]
    try:
        return MultiFernet([Fernet(k) for k in keys])
    except Exception as exc:  # noqa: BLE001 - a bad key must not crash the pipeline
        log.error("indicator_encryption_key_invalid", error=str(exc))
        return None


def encrypt_indicator(value: str | None) -> bytes | None:
    """Encrypt a full indicator value for at-rest storage.

    Returns ``None`` when there is nothing to store or no key is configured
    (fail closed — never returns plaintext). Callers must treat ``None`` as
    "no evidence retained" and carry on; clustering relies on ``value_hash``,
    not on this column.
    """
    if not value:
        return None
    cipher = _cipher()
    if cipher is None:
        if not _WARNED["no_key"]:
            log.warning(
                "indicator_encryption_disabled",
                detail=(
                    "PKINTEL_INDICATOR_ENC_KEY is unset; full indicator values are "
                    "NOT being retained. Clustering is unaffected. Set a key to "
                    "enable abuse-desk evidence."
                ),
            )
            _WARNED["no_key"] = True
        return None
    return cipher.encrypt(value.encode("utf-8"))


def decrypt_indicator(blob: bytes | memoryview | None) -> str | None:
    """Decrypt a stored indicator value. Returns ``None`` if absent/undecryptable.

    Only ever called on the abuse-desk reporting path — never by the public API.
    """
    if not blob:
        return None
    cipher = _cipher()
    if cipher is None:
        return None
    try:
        return cipher.decrypt(bytes(blob)).decode("utf-8")
    except Exception as exc:  # noqa: BLE001 - wrong key / corrupt blob
        log.warning("indicator_decrypt_failed", error=str(exc))
        return None


def encryption_enabled() -> bool:
    """True if a usable key is configured. Surfaced on the health endpoint."""
    return _cipher() is not None
