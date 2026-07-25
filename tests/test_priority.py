"""Tests for work-queue priority (pkintel.ingest.priority).

The property that matters operationally: a fresh CT hit on a UAE priority brand
must outrank a stale bulk-feed URL. That inversion is the whole reason the
column exists — under the old `ORDER BY id` FIFO the CT hit was triaged last.
"""

from __future__ import annotations

import pytest

from pkintel.ingest.priority import DEFAULT_FRESHNESS, SOURCE_FRESHNESS, compute_priority

PRIORITY_BRANDS = ["Emirates NBD", "ADCB", "RTA", "Etisalat", "UAE PASS"]
KNOWN_BRANDS = ["PayPal", "Microsoft", "DHL"]


def prio(url: str, source: str) -> int:
    return compute_priority(
        url,
        source_name=source,
        priority_brands=PRIORITY_BRANDS,
        known_brands=KNOWN_BRANDS,
    )


def test_range_is_clamped_0_100():
    # Maximum stacking: freshest source + priority brand + cred path + bad TLD.
    hi = prio("https://emiratesnbd-login.tk/verify", "certstream")
    assert 0 <= hi <= 100
    lo = prio("https://example.com/", "github")
    assert 0 <= lo <= 100


def test_the_inversion_this_column_exists_to_fix():
    """A fresh CT hit on a UAE brand must beat a stale bulk-feed URL."""
    fresh_uae = prio("https://adcb-secure-login.com/login", "certstream")
    stale_bulk = prio("https://random-compromised-site.com/wp/x.php", "phishing.database")
    assert fresh_uae > stale_bulk
    # And by a wide margin, so it is not a coin flip under FIFO tie-breaking.
    assert fresh_uae - stale_bulk >= 40


def test_priority_brand_beats_known_brand():
    uae = prio("https://emiratesnbd-verify.com/", "urlhaus")
    generic = prio("https://paypal-verify.com/", "urlhaus")
    assert uae > generic


def test_priority_and_known_brand_bonuses_do_not_stack():
    """A priority brand is by definition also a known brand; only one applies."""
    base = prio("https://neutral-host.com/", "urlhaus")
    uae = prio("https://emiratesnbd.evil.com/", "urlhaus")
    assert uae - base == 35  # WEIGHTS["priority_brand_host"], not 35 + 15


def test_separator_insensitive_brand_match():
    """`emirates-nbd` and `emiratesnbd` are the same brand to an attacker."""
    dashed = prio("https://emirates-nbd-secure.com/", "urlhaus")
    solid = prio("https://emiratesnbd-secure.com/", "urlhaus")
    assert dashed == solid


def test_credential_path_hint_adds_weight():
    with_path = prio("https://somehost.com/login", "urlhaus")
    without = prio("https://somehost.com/index", "urlhaus")
    assert with_path - without == 10


def test_suspicious_tld_adds_weight():
    bad = prio("https://somehost.tk/", "urlhaus")
    good = prio("https://somehost.com/", "urlhaus")
    assert bad - good == 5


def test_unknown_source_gets_default_not_zero():
    """A newly added feed must not be silently starved at priority 0."""
    assert prio("https://x.com/", "some-brand-new-feed") == DEFAULT_FRESHNESS


def test_malformed_url_still_gets_base_priority():
    assert prio("not a url at all", "urlhaus") == SOURCE_FRESHNESS["urlhaus"]
    assert prio("", "urlhaus") == SOURCE_FRESHNESS["urlhaus"]


def test_deterministic():
    url = "https://adcb-login.xyz/verify"
    assert len({prio(url, "certstream") for _ in range(10)}) == 1


@pytest.mark.parametrize("source", sorted(SOURCE_FRESHNESS))
def test_every_declared_source_is_in_range(source: str):
    assert 0 <= SOURCE_FRESHNESS[source] <= 100
