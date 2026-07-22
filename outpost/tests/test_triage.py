"""Unit tests for the triage subsystem.

All tests exercise pure functions only — no database, no network. They rely on
inline HTML fixtures and fixed byte samples.
"""

from __future__ import annotations

import base64

import mmh3

from pkintel.triage.brand import detect_brand, keyword_hits
from pkintel.triage.favicon import favicon_mmh3
from pkintel.triage.forms import FormSignal, analyze_forms, registrable_domain
from pkintel.triage.phash import hamming
from pkintel.triage.score import score

# --------------------------------------------------------------------------- #
# favicon
# --------------------------------------------------------------------------- #

_FAVICON_SAMPLE = b"\x00\x01\x02GIF89a-fake-favicon-bytes-\xff\xfe\x89PNG" * 8


def test_favicon_mmh3_follows_recipe_and_is_stable():
    # Matches the documented urlscan/Shodan recipe exactly.
    expected = mmh3.hash(base64.encodebytes(_FAVICON_SAMPLE))
    assert favicon_mmh3(_FAVICON_SAMPLE) == expected
    # Deterministic across repeated calls.
    assert favicon_mmh3(_FAVICON_SAMPLE) == favicon_mmh3(_FAVICON_SAMPLE)
    assert isinstance(favicon_mmh3(_FAVICON_SAMPLE), int)


def test_favicon_mmh3_differs_for_different_bytes():
    assert favicon_mmh3(_FAVICON_SAMPLE) != favicon_mmh3(_FAVICON_SAMPLE + b"x")


# --------------------------------------------------------------------------- #
# phash helper
# --------------------------------------------------------------------------- #


def test_hamming_distance_and_missing_sentinel():
    assert hamming("00000000", "00000000") == 0
    assert hamming("0000000f", "00000000") == 4  # 0xf == 1111 -> 4 bits
    assert hamming(None, "00000000") == 64
    assert hamming("ff", "0000") == 64  # length mismatch -> sentinel


# --------------------------------------------------------------------------- #
# forms
# --------------------------------------------------------------------------- #

_OFFDOMAIN_HTML = """
<html><body>
  <form action="https://evil-collector.ru/save.php" method="post">
    <input type="text" name="user">
    <input type="password" name="pass">
    <button type="submit">Sign in</button>
  </form>
</body></html>
"""

_SAME_DOMAIN_HTML = """
<html><body>
  <form action="/auth/login" method="post">
    <input type="email" name="user">
    <input type="password" name="pass">
  </form>
</body></html>
"""

_SAME_SUBDOMAIN_HTML = """
<html><body>
  <form action="https://www.victim-bank.com/login" method="post">
    <input type="password" name="pass">
  </form>
</body></html>
"""

_NO_FORM_HTML = "<html><body><p>Just a page.</p></body></html>"

_PAGE_URL = "https://login.victim-bank.com/signin"


def test_offdomain_password_post_is_suspicious():
    sig = analyze_forms(_OFFDOMAIN_HTML, _PAGE_URL)
    assert sig.has_password_field is True
    assert sig.posts_offdomain is True
    assert sig.suspicious is True
    assert "evil-collector.ru" in sig.action_hosts


def test_same_domain_login_is_not_suspicious():
    sig = analyze_forms(_SAME_DOMAIN_HTML, _PAGE_URL)
    assert sig.has_password_field is True
    assert sig.posts_offdomain is False
    assert sig.suspicious is False


def test_same_registrable_domain_across_subdomains_not_suspicious():
    sig = analyze_forms(_SAME_SUBDOMAIN_HTML, _PAGE_URL)
    assert sig.has_password_field is True
    assert sig.suspicious is False


def test_no_form_is_not_suspicious():
    sig = analyze_forms(_NO_FORM_HTML, _PAGE_URL)
    assert sig.has_password_field is False
    assert sig.suspicious is False


def test_empty_html_is_safe():
    sig = analyze_forms(None, _PAGE_URL)
    assert sig == FormSignal()


def test_registrable_domain():
    assert registrable_domain("login.victim-bank.com") == "victim-bank.com"
    assert registrable_domain("a.b.example.co.uk") == "example.co.uk"
    assert registrable_domain("example.com") == "example.com"
    assert registrable_domain("host.example.com:8443") == "example.com"


# --------------------------------------------------------------------------- #
# brand
# --------------------------------------------------------------------------- #


def test_priority_brand_wins_over_generic():
    html = (
        "<html><head><title>Emirates NBD Online Banking</title></head>"
        "<body>Sign in with your Microsoft account</body></html>"
    )
    brand, reasons = detect_brand(
        html, "http://enbd-secure.example/login", ["Emirates NBD", "Emirates"]
    )
    assert brand == "Emirates NBD"
    assert reasons


def test_generic_brand_detected_when_no_priority_match():
    html = "<html><head><title>PayPal - Log In</title></head><body>Log in</body></html>"
    brand, reasons = detect_brand(html, "http://paypa1.example/", ["ADCB", "FAB"])
    assert brand == "PayPal"
    assert reasons


def test_no_brand_returns_none():
    brand, reasons = detect_brand(
        "<html><body>hello world</body></html>", "http://example.com/", ["ADCB"]
    )
    assert brand is None
    assert reasons == []


def test_keyword_hits_counts_distinct_phrases():
    html = (
        "<html><body>Please verify your identity and sign in to avoid your "
        "account suspended.</body></html>"
    )
    n, hits = keyword_hits(html, "http://x/")
    assert n >= 2
    assert "verify your identity" in hits


# --------------------------------------------------------------------------- #
# score
# --------------------------------------------------------------------------- #


def test_score_is_monotonic_in_signals():
    off_form = FormSignal(has_password_field=True, posts_offdomain=True, suspicious=True)
    s0 = score(is_live=True, threshold=50).score
    s1 = score(is_live=True, brand="PayPal", threshold=50).score
    s2 = score(is_live=True, brand="PayPal", keyword_hits=3, threshold=50).score
    s3 = score(is_live=True, brand="PayPal", keyword_hits=3, form=off_form, threshold=50).score
    assert s0 < s1 < s2 < s3


def test_offdomain_form_scores_higher_than_same_domain_login():
    same = FormSignal(has_password_field=True, posts_offdomain=False, suspicious=False)
    off = FormSignal(has_password_field=True, posts_offdomain=True, suspicious=True)
    assert (
        score(is_live=True, form=off, threshold=50).score
        > score(is_live=True, form=same, threshold=50).score
    )


def test_score_clamped_to_100():
    off = FormSignal(has_password_field=True, posts_offdomain=True, suspicious=True)
    result = score(
        is_live=True,
        brand="Emirates NBD",
        brand_is_priority=True,
        favicon_brand="Emirates NBD",
        form=off,
        keyword_hits=10,
        logo_match=True,
        threshold=50,
    )
    assert result.score == 100


def test_threshold_behaviour():
    off = FormSignal(has_password_field=True, posts_offdomain=True, suspicious=True)
    strong = score(
        is_live=True,
        brand="Emirates NBD",
        brand_is_priority=True,
        form=off,
        keyword_hits=5,
        threshold=50,
    )
    assert strong.is_phish is True
    assert strong.score >= 50

    weak = score(is_live=True, threshold=50)  # only "live" -> 5
    assert weak.is_phish is False
    assert weak.score < 50


def test_dead_page_scores_zero_and_not_phish():
    result = score(is_live=False, threshold=50)
    assert result.score == 0
    assert result.is_phish is False
    assert result.is_live is False
