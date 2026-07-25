"""Tests for brand-lookalike matching (pkintel.ingest.typosquat).

False positives matter more than usual here. This matcher runs against every
DNS name in every certificate issued on the public internet, so a sloppy rule
does not just add noise — it floods the triage queue and starves the real hits.
The "must NOT match" cases below are therefore the important half of this file.
"""

from __future__ import annotations

import pytest

from pkintel.ingest.typosquat import (
    BrandMatcher,
    edit_distance_within,
    normalize_homoglyphs,
)

BRANDS = ["Emirates NBD", "ADCB", "Etisalat", "Mashreq", "du", "UAE PASS", "Dubai Police"]


@pytest.fixture(scope="module")
def matcher() -> BrandMatcher:
    return BrandMatcher(BRANDS, max_edit_distance=2)


# --------------------------------------------------------------------------- edit distance
def test_edit_distance_basic():
    assert edit_distance_within("abc", "abc", 2) == 0
    assert edit_distance_within("abc", "abd", 2) == 1
    assert edit_distance_within("abc", "axd", 2) == 2


def test_edit_distance_returns_none_past_budget():
    assert edit_distance_within("abc", "xyz", 2) is None
    assert edit_distance_within("short", "muchlongerstring", 2) is None


def test_edit_distance_is_symmetric():
    for a, b in [("emiratesnbd", "emiratesnbcl"), ("adcb", "adbc"), ("kitten", "sittin")]:
        assert edit_distance_within(a, b, 3) == edit_distance_within(b, a, 3)


# --------------------------------------------------------------------------- homoglyphs
def test_homoglyph_normalisation():
    assert normalize_homoglyphs("emirat3snbd") == normalize_homoglyphs("emiratesnbd")
    assert normalize_homoglyphs("g00gle") == "google"


def test_digraph_rn_to_m():
    """rn -> m is the highest-yield typosquat trick in the wild."""
    assert normalize_homoglyphs("rnashreq") == normalize_homoglyphs("mashreq")


def test_cyrillic_homoglyph_folds():
    # Cyrillic 'а' (U+0430) is visually identical to Latin 'a'.
    assert normalize_homoglyphs("аdcb") == "adcb"


# --------------------------------------------------------------------------- true positives
@pytest.mark.parametrize(
    "host,expected_brand",
    [
        ("emiratesnbd-secure.com", "Emirates NBD"),
        ("emirates-nbd-login.net", "Emirates NBD"),
        ("secure-emiratesnbd.verify.xyz", "Emirates NBD"),
        ("emirat3snbd.com", "Emirates NBD"),        # homoglyph
        ("etisalat-billing.top", "Etisalat"),
        ("rnashreq-online.com", "Mashreq"),          # rn -> m
        ("uaepass-verify.xyz", "UAE PASS"),
        ("dubaipolice-fine.click", "Dubai Police"),
    ],
)
def test_matches_real_lookalikes(matcher: BrandMatcher, host: str, expected_brand: str):
    result = matcher.match(host)
    assert result is not None, f"{host} should have matched {expected_brand}"
    assert result[0] == expected_brand


def test_typo_variant_matches(matcher: BrandMatcher):
    # one deletion from 'emiratesnbd'
    result = matcher.match("emiratesnb.com")
    assert result is not None
    assert result[0] == "Emirates NBD"
    assert result[1] in {"typo", "homoglyph"}


def test_reason_is_reported(matcher: BrandMatcher):
    brand, reason = matcher.match("emiratesnbd-login.com")
    assert brand == "Emirates NBD"
    assert reason == "combosquat"


# --------------------------------------------------------------------------- false positives
@pytest.mark.parametrize(
    "host",
    [
        # The brands' own domains are not phishing.
        "emiratesnbd.ae",
        "www.emiratesnbd.ae",
        "adcb.com",
        "www.adcb.com",
        # Ordinary internet that must not be dragged in.
        "google.com",
        "github.com",
        "en.wikipedia.org",
        "mail.google.com",
        "cdn.jsdelivr.net",
        "amazonaws.com",
    ],
)
def test_does_not_match_innocent_hosts(matcher: BrandMatcher, host: str):
    assert matcher.match(host) is None, f"false positive on {host}"


@pytest.mark.parametrize(
    "host",
    [
        "education.com",     # contains 'du'
        "produce-mart.net",  # contains 'du'
        "schedule-app.io",   # contains 'du'
        "duckduckgo.com",    # contains 'du'
    ],
)
def test_short_brand_does_not_flood(matcher: BrandMatcher, host: str):
    """'du' is 2 chars. Without the MIN_FUZZY_LEN guard it matches half the web."""
    assert matcher.match(host) is None, f"short-brand false positive on {host}"


def test_short_brand_still_matches_with_a_lure(matcher: BrandMatcher):
    """'du' alone is noise, but 'du' + a lure token is reportable."""
    result = matcher.match("du-account-verify.xyz")
    assert result is not None
    assert result[0] == "du"


# --------------------------------------------------------------------------- robustness
@pytest.mark.parametrize("host", ["", "   ", "not a host", "localhost", "...", "a"])
def test_malformed_input_is_safe(matcher: BrandMatcher, host: str):
    assert matcher.match(host) is None


def test_wildcard_and_trailing_dot_are_stripped(matcher: BrandMatcher):
    assert matcher.match("*.emiratesnbd-login.com") is not None
    assert matcher.match("emiratesnbd-login.com.") is not None


def test_case_insensitive(matcher: BrandMatcher):
    assert matcher.match("EmiratesNBD-Secure.COM") is not None


def test_deterministic(matcher: BrandMatcher):
    host = "emiratesnbd-verify.xyz"
    assert len({matcher.match(host) for _ in range(20)}) == 1


def test_throughput_is_firehose_viable(matcher: BrandMatcher):
    """Must sustain CT firehose volume (~400 certs/sec, several names each).

    Budget: 5000 hostnames well under a second on one thread.
    """
    import time

    hosts = [f"host{i}-cdn.example{i % 50}.com" for i in range(5000)]
    started = time.monotonic()
    for h in hosts:
        matcher.match(h)
    elapsed = time.monotonic() - started
    assert elapsed < 1.0, f"{len(hosts)} hosts took {elapsed:.2f}s — too slow for the firehose"
