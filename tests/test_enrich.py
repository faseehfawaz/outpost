"""Tests for host enrichment parsing (pkintel.enrich).

Pure parsers only — no DNS queries, no TLS handshakes. These are the functions
that turn wire formats into the facts the pivot graph clusters on, so a silent
parsing bug here would degrade the pivot invisibly.
"""

from __future__ import annotations

from datetime import timezone

import pytest

from pkintel.enrich.dnsinfo import (
    parse_cymru_asname,
    parse_cymru_origin,
    reverse_octets,
)
from pkintel.enrich.tlscert import extract_names, format_dn, parse_cert_datetime


# --------------------------------------------------------------------------- reverse_octets
def test_reverse_octets_basic():
    assert reverse_octets("104.21.5.7") == "7.5.21.104"
    assert reverse_octets("8.8.8.8") == "8.8.8.8"


@pytest.mark.parametrize(
    "bad",
    ["", "not.an.ip", "1.2.3", "1.2.3.4.5", "999.1.1.1", "2001:db8::1", "a.b.c.d"],
)
def test_reverse_octets_rejects_non_ipv4(bad: str):
    assert reverse_octets(bad) is None


# --------------------------------------------------------------------------- cymru origin
def test_parse_cymru_origin():
    info = parse_cymru_origin("13335 | 104.16.0.0/12 | US | arin | 2010-07-14")
    assert info.asn == 13335
    assert info.prefix == "104.16.0.0/12"
    assert info.country == "US"


def test_parse_cymru_origin_strips_quotes():
    info = parse_cymru_origin('"13335 | 104.16.0.0/12 | US | arin | 2010-07-14"')
    assert info.asn == 13335


def test_parse_cymru_origin_multi_asn_takes_first():
    """An IP announced by several ASNs lists them space-separated; take the origin."""
    info = parse_cymru_origin("13335 20940 | 104.16.0.0/12 | US | arin | 2010-07-14")
    assert info.asn == 13335


@pytest.mark.parametrize("bad", ["", "   ", "garbage", "| | |", "notanumber | x | y"])
def test_parse_cymru_origin_handles_garbage(bad: str):
    info = parse_cymru_origin(bad)
    assert info.asn is None


# --------------------------------------------------------------------------- cymru asname
def test_parse_cymru_asname():
    txt = "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
    assert parse_cymru_asname(txt) == "CLOUDFLARENET, US"


def test_parse_cymru_asname_too_few_fields():
    assert parse_cymru_asname("13335 | US") is None
    assert parse_cymru_asname("") is None


# --------------------------------------------------------------------------- cert datetimes
def test_parse_cert_datetime_openssl_format():
    dt = parse_cert_datetime("Jun  1 12:00:00 2026 GMT")
    assert dt is not None
    assert dt.year == 2026
    assert dt.month == 6
    assert dt.day == 1
    assert dt.hour == 12


def test_parse_cert_datetime_is_timezone_aware():
    """Naive datetimes would compare incorrectly against now(timezone.utc)."""
    dt = parse_cert_datetime("Jun  1 12:00:00 2026 GMT")
    assert dt.tzinfo is not None
    assert dt.utcoffset() == timezone.utc.utcoffset(None)


@pytest.mark.parametrize("bad", [None, "", "not a date", "2026-06-01"])
def test_parse_cert_datetime_handles_garbage(bad):
    assert parse_cert_datetime(bad) is None


# --------------------------------------------------------------------------- cert names
def test_extract_names_from_san():
    cert = {
        "subjectAltName": (
            ("DNS", "adcb-login.com"),
            ("DNS", "adcb-verify.com"),
            ("DNS", "www.adcb-login.com"),
        )
    }
    names = extract_names(cert)
    assert names == ["adcb-login.com", "adcb-verify.com", "www.adcb-login.com"]


def test_extract_names_unwraps_wildcards():
    """`*.evil.com` and `evil.com` are the same domain for pivoting."""
    cert = {"subjectAltName": (("DNS", "*.evil.com"), ("DNS", "evil.com"))}
    assert extract_names(cert) == ["evil.com"]


def test_extract_names_includes_legacy_common_name():
    cert = {
        "subjectAltName": (("DNS", "a.com"),),
        "subject": ((("commonName", "b.com"),),),
    }
    names = extract_names(cert)
    assert "a.com" in names
    assert "b.com" in names


def test_extract_names_deduplicates_and_lowercases():
    cert = {
        "subjectAltName": (("DNS", "A.COM"), ("DNS", "a.com"), ("DNS", "a.com.")),
    }
    assert extract_names(cert) == ["a.com"]


def test_extract_names_ignores_non_dns_san_entries():
    cert = {"subjectAltName": (("IP Address", "1.2.3.4"), ("DNS", "a.com"))}
    assert extract_names(cert) == ["a.com"]


@pytest.mark.parametrize("bad", [None, {}, {"subjectAltName": ()}])
def test_extract_names_handles_empty(bad):
    assert extract_names(bad) == []


def test_the_discovery_scenario():
    """One handshake reveals the operator's whole portfolio.

    This is the payoff: siblings that appear in no public feed.
    """
    cert = {
        "subjectAltName": (
            ("DNS", "adcb-login.com"),
            ("DNS", "emiratesnbd-verify.com"),
            ("DNS", "mashreq-secure.net"),
            ("DNS", "*.rta-fines.xyz"),
        )
    }
    names = extract_names(cert)
    assert len(names) == 4
    assert "rta-fines.xyz" in names  # wildcard unwrapped


# --------------------------------------------------------------------------- DN formatting
def test_format_dn():
    dn = ((("countryName", "US"),), (("organizationName", "Let's Encrypt"),), (("commonName", "R3"),))
    out = format_dn(dn)
    assert "commonName=R3" in out
    assert "organizationName=Let's Encrypt" in out


def test_format_dn_empty():
    assert format_dn(None) is None
    assert format_dn(()) is None
