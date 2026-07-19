"""Unit tests for the ingest subsystem.

Everything here runs WITHOUT a database or network: we exercise the pure
canonicalisation / hashing / parsing helpers with inline sample data. The few
tests that touch the runner import only its *pure* functions (``build_adapters``,
``_normalize_candidates``) and are skipped if the heavier import chain
(pydantic/psycopg) is not installed.
"""

from __future__ import annotations

import types

import pytest

from pkintel.ingest.base import parse_url_lines
from pkintel.ingest.ct import (
    brand_slug,
    crtsh_query_url,
    looks_like_lookalike,
    parse_crtsh_json,
)
from pkintel.ingest.normalize import canonical_url, host_of, url_hash
from pkintel.ingest.urlhaus import parse_urlhaus_csv
from pkintel.ingest.urlscan import parse_urlscan_json
from pkintel.redact import sha256_hex

try:  # runner drags in pydantic/psycopg; only its pure fns are tested
    from pkintel.ingest.runner import _normalize_candidates, build_adapters

    _RUNNER_OK = True
except Exception:  # pragma: no cover - env without the full stack
    _RUNNER_OK = False


# --------------------------------------------------------------------------- #
# canonical_url
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "raw, expected",
    [
        # scheme + host lowercased, path case preserved
        ("HTTP://Example.COM/Path", "http://example.com/Path"),
        # default port stripped, bare-host trailing slash dropped
        ("http://example.com:80/", "http://example.com"),
        ("https://example.com:443/a", "https://example.com/a"),
        # bare host with/without trailing slash collapse to the same thing
        ("http://example.com/", "http://example.com"),
        ("http://example.com", "http://example.com"),
        # trailing slash kept on a real path
        ("http://example.com/a/", "http://example.com/a/"),
        # fragment dropped, query kept
        ("http://example.com/a#frag", "http://example.com/a"),
        ("http://example.com/a?b=1&c=2", "http://example.com/a?b=1&c=2"),
        # missing scheme -> http:// added
        ("example.com/login", "http://example.com/login"),
        # trailing dot on host removed
        ("http://example.com./", "http://example.com"),
        # non-default port preserved (but bare-host slash still dropped)
        ("http://example.com:8080/", "http://example.com:8080"),
        # surrounding whitespace ignored
        ("  http://example.com/x  ", "http://example.com/x"),
    ],
)
def test_canonical_url(raw, expected):
    assert canonical_url(raw) == expected


def test_canonical_url_idempotent():
    for raw in [
        "HTTP://Example.COM:80/Path?q=1#frag",
        "example.com",
        "https://a.b.example.com:443/deep/path/",
        "http://user@Example.com:8080/x",
    ]:
        once = canonical_url(raw)
        assert canonical_url(once) == once


def test_canonical_url_dedupes_trivial_variants():
    variants = [
        "HTTP://Example.com:80/",
        "http://example.com",
        "http://Example.COM./",
        "  http://example.com#top  ",
    ]
    canon = {canonical_url(v) for v in variants}
    assert canon == {"http://example.com"}
    hashes = {url_hash(canonical_url(v)) for v in variants}
    assert len(hashes) == 1


def test_canonical_url_ipv6_default_port():
    assert canonical_url("http://[::1]:80/") == "http://[::1]"


def test_canonical_url_preserves_userinfo_but_lowercases_host():
    assert canonical_url("https://User@Example.com:8443/x") == "https://User@example.com:8443/x"


@pytest.mark.parametrize("bad", ["", "   ", "http://", "https://#frag"])
def test_canonical_url_rejects_hostless(bad):
    with pytest.raises(ValueError):
        canonical_url(bad)


# --------------------------------------------------------------------------- #
# url_hash
# --------------------------------------------------------------------------- #
def test_url_hash_is_sha256_of_canonical():
    canon = canonical_url("http://example.com/a")
    h = url_hash(canon)
    assert h == sha256_hex(canon)
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


def test_url_hash_distinguishes_different_urls():
    assert url_hash(canonical_url("http://a.example/")) != url_hash(
        canonical_url("http://b.example/")
    )


# --------------------------------------------------------------------------- #
# host_of
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "url, host",
    [
        ("https://User@Example.com:8443/x?y=1", "example.com"),
        ("example.com/login", "example.com"),
        ("HTTP://SUB.Example.COM/", "sub.example.com"),
        ("http://example.com./a", "example.com"),
        ("http://[2001:db8::1]:8443/x", "[2001:db8::1]"),
        ("", ""),
        ("   ", ""),
    ],
)
def test_host_of(url, host):
    assert host_of(url) == host


# --------------------------------------------------------------------------- #
# URLhaus CSV parsing
# --------------------------------------------------------------------------- #
URLHAUS_SAMPLE = (
    "# URLhaus recent feed\n"
    "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
    '"1","2026-07-18 10:00:00","http://a.example/login","online","2026-07-18","phishing","tag","https://urlhaus.abuse.ch/url/1/","bob"\n'
    '"2","2026-07-18 10:01:00","http://b.example/","online","2026-07-18","phishing","tag","https://urlhaus.abuse.ch/url/2/","alice"\n'
    "\n"
    '"3","2026-07-18 10:02:00","https://c.example/pay?id=9","online","2026-07-18","phishing","","https://urlhaus.abuse.ch/url/3/","carol"\n'
)


def test_parse_urlhaus_csv():
    urls = list(parse_urlhaus_csv(URLHAUS_SAMPLE))
    assert urls == [
        "http://a.example/login",
        "http://b.example/",
        "https://c.example/pay?id=9",
    ]


def test_parse_urlhaus_csv_empty_and_comment_only():
    assert list(parse_urlhaus_csv("")) == []
    assert list(parse_urlhaus_csv("# only a comment\n#another\n")) == []


# --------------------------------------------------------------------------- #
# Line-list parsing (OpenPhish / GitHub)
# --------------------------------------------------------------------------- #
LINES_SAMPLE = (
    "http://x.example/a\n"
    "# a comment line\n"
    "   \n"
    "  https://y.example/b  \n"
    "z.example/c\n"
)


def test_parse_url_lines():
    assert list(parse_url_lines(LINES_SAMPLE)) == [
        "http://x.example/a",
        "https://y.example/b",
        "z.example/c",
    ]


# --------------------------------------------------------------------------- #
# urlscan JSON parsing
# --------------------------------------------------------------------------- #
def test_parse_urlscan_json():
    payload = {
        "results": [
            {"page": {"url": "http://p1.example/"}},
            {"page": {"url": "https://p2.example/x"}},
            {"page": {}},           # no url
            {"nope": 1},            # no page
            "garbage",              # not a dict
        ]
    }
    assert list(parse_urlscan_json(payload)) == [
        "http://p1.example/",
        "https://p2.example/x",
    ]


def test_parse_urlscan_json_tolerates_junk():
    assert list(parse_urlscan_json(None)) == []
    assert list(parse_urlscan_json({"results": "nope"})) == []
    assert list(parse_urlscan_json([])) == []


# --------------------------------------------------------------------------- #
# Certificate Transparency helpers
# --------------------------------------------------------------------------- #
def test_brand_slug_and_query_url():
    assert brand_slug("Emirates NBD") == "emiratesnbd"
    assert brand_slug("du") == "du"
    assert crtsh_query_url("Emirates NBD") == (
        "https://crt.sh/?q=%25emiratesnbd%25&output=json"
    )


@pytest.mark.parametrize(
    "host, expected",
    [
        ("emiratesnbd-login.com", True),      # combosquat
        ("emirates-nbd.net", True),           # hyphenated squat
        ("secure-emiratesnbd.xyz", True),     # prefixed squat
        ("emiratesnbd.com", False),           # the brand's own domain
        ("www.emiratesnbd.com", False),       # subdomain of the brand
        ("login.emiratesnbd.com", False),     # subdomain of the brand family
        ("example.com", False),               # unrelated
        ("emiratesnbd", False),               # single label, no TLD
    ],
)
def test_looks_like_lookalike(host, expected):
    assert looks_like_lookalike(host, "emiratesnbd") is expected


def test_parse_crtsh_json():
    payload = [
        {
            "common_name": "emiratesnbd-login.com",
            "name_value": "emiratesnbd-login.com\nwww.emiratesnbd.com\nemirates-nbd.net",
        },
        {"common_name": "*.secure-emiratesnbd.xyz"},
        {"nope": "ignored"},
    ]
    hosts = list(parse_crtsh_json(payload, "emiratesnbd"))
    assert hosts == [
        "emiratesnbd-login.com",
        "emirates-nbd.net",
        "secure-emiratesnbd.xyz",
    ]


def test_parse_crtsh_json_tolerates_junk():
    assert list(parse_crtsh_json(None, "emiratesnbd")) == []
    assert list(parse_crtsh_json({"not": "a list"}, "emiratesnbd")) == []


# --------------------------------------------------------------------------- #
# runner pure functions (skipped without the full stack)
# --------------------------------------------------------------------------- #
def _fake_settings(**overrides):
    base = dict(
        urlhaus_enabled=True,
        openphish_enabled=True,
        urlscan_api_key="",
        ct_enabled=True,
        priority_brands=["Emirates NBD"],
    )
    base.update(overrides)
    return types.SimpleNamespace(**base)


@pytest.mark.skipif(not _RUNNER_OK, reason="runner import stack unavailable")
def test_build_adapters_respects_flags():
    all_on = {a.name for a in build_adapters(_fake_settings(urlscan_api_key="k"))}
    assert all_on == {"urlhaus", "openphish", "urlscan", "crtsh", "github"}

    minimal = {
        a.name
        for a in build_adapters(
            _fake_settings(
                urlhaus_enabled=False,
                openphish_enabled=False,
                ct_enabled=False,
            )
        )
    }
    assert minimal == {"github"}  # github needs no key/flag


@pytest.mark.skipif(not _RUNNER_OK, reason="runner import stack unavailable")
def test_normalize_candidates_dedupes_and_caps():
    raws = [
        "HTTP://Example.com:80/",
        "http://example.com",           # dup of the first
        "http://example.com/a",
        "",                             # unpar-seable -> skipped
        "http://example.com/a#frag",    # dup of /a after fragment strip
    ]
    rows = _normalize_candidates(raws, cap=10)
    canon = [c for c, _h, _host in rows]
    assert canon == ["http://example.com", "http://example.com/a"]
    assert all(host == "example.com" for _c, _h, host in rows)

    # cap is honoured
    assert len(_normalize_candidates(raws, cap=1)) == 1
