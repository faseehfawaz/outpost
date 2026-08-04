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

from pkintel.ingest.apwg import CommunityListsAdapter, parse_community_feed
from pkintel.ingest.base import parse_url_lines
from pkintel.ingest.ct import (
    brand_slug,
    crtsh_query_url,
    looks_like_lookalike,
    parse_crtsh_json,
)
from pkintel.ingest.emerging import MaltrailAdapter, parse_domain_lines
from pkintel.ingest.normalize import canonical_url, host_of, url_hash
from pkintel.ingest.otx import OTXAdapter, parse_otx_json
from pkintel.ingest.phishunt import parse_phishunt_json
from pkintel.ingest.stalkphish import StalkPhishAdapter, parse_stalkphish_json
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
LINES_SAMPLE = "http://x.example/a\n# a comment line\n   \n  https://y.example/b  \nz.example/c\n"


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
            {"page": {}},  # no url
            {"nope": 1},  # no page
            "garbage",  # not a dict
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
    assert crtsh_query_url("Emirates NBD") == ("https://crt.sh/?q=%25emiratesnbd%25&output=json")


@pytest.mark.parametrize(
    "host, expected",
    [
        ("emiratesnbd-login.com", True),  # combosquat
        ("emirates-nbd.net", True),  # hyphenated squat
        ("secure-emiratesnbd.xyz", True),  # prefixed squat
        ("emiratesnbd.com", False),  # the brand's own domain
        ("www.emiratesnbd.com", False),  # subdomain of the brand
        ("login.emiratesnbd.com", False),  # subdomain of the brand family
        ("example.com", False),  # unrelated
        ("emiratesnbd", False),  # single label, no TLD
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
# OTX JSON parsing
# --------------------------------------------------------------------------- #
def test_parse_otx_json():
    payload = {
        "results": [
            {
                "indicators": [
                    {"type": "URL", "indicator": "http://phish.example/login.php"},
                    {"type": "domain", "indicator": "evil-domain.com"},
                    {"type": "hostname", "indicator": "sub.phish.com"},
                    {"type": "IPv4", "indicator": "1.2.3.4"},  # filtered out
                    {"type": "FileHash-SHA256", "indicator": "abc123def"},  # filtered out
                ]
            },
            {
                "indicators": [
                    {"type": "URL", "indicator": "https://secure.example/auth"},
                ]
            },
        ],
        "next": "https://otx.alienvault.com/api/v1/search/pulses?q=phishing&limit=50&page=2",
    }
    extracted = list(parse_otx_json(payload))
    assert extracted == [
        "http://phish.example/login.php",
        "http://evil-domain.com/",
        "http://sub.phish.com/",
        "https://secure.example/auth",
    ]


def test_parse_otx_json_tolerates_junk():
    assert list(parse_otx_json(None)) == []
    assert list(parse_otx_json({})) == []
    assert list(parse_otx_json({"results": "invalid"})) == []


def test_otx_adapter_fetch_and_pagination(monkeypatch):
    from unittest.mock import MagicMock

    adapter = OTXAdapter()
    assert adapter.name == "otx"
    assert adapter.kind == "otx"

    page1_resp = MagicMock()
    page1_resp.status_code = 200
    page1_resp.json.return_value = {
        "results": [
            {
                "indicators": [
                    {"type": "URL", "indicator": "http://p1.example/phish"},
                ]
            }
        ],
        "next": "https://otx.alienvault.com/api/v1/search/pulses?q=phishing&limit=50&page=2",
    }

    page2_resp = MagicMock()
    page2_resp.status_code = 200
    page2_resp.json.return_value = {
        "results": [
            {
                "indicators": [
                    {"type": "domain", "indicator": "p2-phish.com"},
                ]
            }
        ],
        "next": None,
    }

    def fake_polite_fetch(client, url, **kwargs):
        if "page=2" in url:
            return page2_resp
        return page1_resp

    monkeypatch.setattr("pkintel.ingest.otx.polite_fetch", fake_polite_fetch)

    urls = list(adapter.fetch(MagicMock()))
    assert urls == ["http://p1.example/phish", "http://p2-phish.com/"]


# --------------------------------------------------------------------------- #
# Phishunt JSON parsing
# --------------------------------------------------------------------------- #
def test_parse_phishunt_json():
    payload = [
        {"url": "http://phish1.example/login"},
        {"url": "  https://phish2.example/auth  "},
        {"url": ""},
        {"other": "value"},
        "not a dict",
    ]
    assert list(parse_phishunt_json(payload)) == [
        "http://phish1.example/login",
        "https://phish2.example/auth",
    ]


def test_parse_phishunt_json_tolerates_junk():
    assert list(parse_phishunt_json(None)) == []
    assert list(parse_phishunt_json({})) == []
    assert list(parse_phishunt_json("invalid")) == []


# --------------------------------------------------------------------------- #
# StalkPhish JSON parsing & Adapter
# --------------------------------------------------------------------------- #
def test_parse_stalkphish_json():
    payload = [
        {"url": "http://stalk.example/login"},
        {"url": "https://bad.example/phish"},
        {"url": ""},
        {"other": "data"},
        "not a dict",
    ]
    assert list(parse_stalkphish_json(payload)) == [
        "http://stalk.example/login",
        "https://bad.example/phish",
    ]


def test_parse_stalkphish_json_tolerates_junk():
    assert list(parse_stalkphish_json(None)) == []
    assert list(parse_stalkphish_json({})) == []
    assert list(parse_stalkphish_json("invalid")) == []


def test_stalkphish_adapter_api_success(monkeypatch):
    from unittest.mock import MagicMock

    adapter = StalkPhishAdapter()
    assert adapter.name == "stalkphish"
    assert adapter.kind == "stalkphish"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [{"url": "http://stalk-api.example/phish"}]

    def fake_polite_fetch(client, url, **kwargs):
        if "api.stalkphish.io" in url:
            return mock_resp
        return None

    monkeypatch.setattr("pkintel.ingest.stalkphish.polite_fetch", fake_polite_fetch)

    urls = list(adapter.fetch(MagicMock()))
    assert urls == ["http://stalk-api.example/phish"]


def test_stalkphish_adapter_fallback_on_api_failure(monkeypatch):
    from unittest.mock import MagicMock

    adapter = StalkPhishAdapter()

    api_resp = MagicMock()
    api_resp.status_code = 500

    fallback_resp = MagicMock()
    fallback_resp.status_code = 200
    fallback_resp.text = "http://stalk-fallback.example/phish\n# comment\n"

    def fake_polite_fetch(client, url, **kwargs):
        if "api.stalkphish.io" in url:
            return api_resp
        if "raw.githubusercontent.com" in url:
            return fallback_resp
        return None

    monkeypatch.setattr("pkintel.ingest.stalkphish.polite_fetch", fake_polite_fetch)

    urls = list(adapter.fetch(MagicMock()))
    assert urls == ["http://stalk-fallback.example/phish"]


# --------------------------------------------------------------------------- #
# Maltrail & Community Domain List parsing & Adapter
# --------------------------------------------------------------------------- #
def test_parse_domain_lines():
    sample = (
        "discord-app.xyz\n# comment line\n   \nhttps://already-url.com/path\nmaltrail-bad.org/\n"
    )
    assert list(parse_domain_lines(sample)) == [
        "http://discord-app.xyz/",
        "https://already-url.com/path",
        "http://maltrail-bad.org/",
    ]


def test_maltrail_adapter_fetch(monkeypatch):
    from unittest.mock import MagicMock

    adapter = MaltrailAdapter()
    assert adapter.name == "maltrail"
    assert adapter.kind == "community"

    resp1 = MagicMock()
    resp1.status_code = 200
    resp1.text = "disc1.xyz\ndisc2.xyz"

    resp2 = MagicMock()
    resp2.status_code = 200
    resp2.text = "mal1.org\n# comment\nmal2.org"

    resp3 = MagicMock()
    resp3.status_code = 500

    responses = [resp1, resp2, resp3]

    def fake_polite_fetch(client, url, **kwargs):
        if responses:
            return responses.pop(0)
        return None

    monkeypatch.setattr("pkintel.ingest.emerging.polite_fetch", fake_polite_fetch)

    urls = list(adapter.fetch(MagicMock()))
    assert urls == [
        "http://disc1.xyz/",
        "http://disc2.xyz/",
        "http://mal1.org/",
        "http://mal2.org/",
    ]


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
    assert "phishunt" in all_on
    assert "stalkphish" in all_on
    assert "otx" in all_on
    assert "maltrail" in all_on
    assert {
        "urlhaus",
        "openphish",
        "urlscan",
        "crtsh",
        "github",
        "phishstats",
        "phishing_database",
        "threatfox",
        "phishunt",
        "stalkphish",
        "otx",
        "maltrail",
        "community_lists",
    }.issubset(all_on)

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
    assert "phishunt" in minimal
    assert "stalkphish" in minimal
    assert "otx" in minimal
    assert "maltrail" in minimal
    assert "community_lists" in minimal


# --------------------------------------------------------------------------- #
# Community Lists parsing (apwg.py)
# --------------------------------------------------------------------------- #
def test_parse_community_feed_hosts():
    sample = (
        "# Phishing filter hosts list\n"
        "0.0.0.0 evil1.com\n"
        "127.0.0.1 evil2.org # comment\n"
        "\n"
        "# Another comment\n"
        "0.0.0.0  sub.phishing-domain.net  \n"
        "::1 localhost\n"  # not starting with 0.0.0.0 or 127.0.0.1
    )
    urls = list(parse_community_feed(sample, "hosts"))
    assert urls == [
        "http://evil1.com/",
        "http://evil2.org/",
        "http://sub.phishing-domain.net/",
    ]


def test_parse_community_feed_domain_list():
    sample = (
        "# Google hostnames light\n"
        "malicious.goolge-fake.com\n"
        "http://already-url.com/login\n"
        "  scam-bank.de  \n"
    )
    urls = list(parse_community_feed(sample, "domain_list"))
    assert urls == [
        "http://malicious.goolge-fake.com/",
        "http://already-url.com/login",
        "http://scam-bank.de/",
    ]


def test_parse_community_feed_url_list():
    sample = "# Plain URL list\nhttp://phish-site.org/index.html\nhttps://secure-bank.top/auth\n"
    urls = list(parse_community_feed(sample, "url_list"))
    assert urls == [
        "http://phish-site.org/index.html",
        "https://secure-bank.top/auth",
    ]


def test_community_lists_adapter_metadata():
    adapter = CommunityListsAdapter()
    assert adapter.name == "community_lists"
    assert adapter.kind == "community"


@pytest.mark.skipif(not _RUNNER_OK, reason="runner import stack unavailable")
def test_normalize_candidates_dedupes_and_caps():
    raws = [
        "HTTP://Example.com:80/",
        "http://example.com",  # dup of the first
        "http://example.com/a",
        "",  # unpar-seable -> skipped
        "http://example.com/a#frag",  # dup of /a after fragment strip
    ]
    rows = _normalize_candidates(raws, cap=10)
    canon = [c for c, _h, _host in rows]
    assert canon == ["http://example.com", "http://example.com/a"]
    assert all(host == "example.com" for _c, _h, host in rows)

    # cap is honoured
    assert len(_normalize_candidates(raws, cap=1)) == 1
