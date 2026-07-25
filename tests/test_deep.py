"""Tests for rendered-signal scoring (pkintel.triage.deep).

Pure functions only — no browser is launched here.
"""

from __future__ import annotations

from pkintel.models import TriageResult
from pkintel.triage.deep import (
    BrandScreenshot,
    deep_score,
    hamming,
    match_brand_screenshot,
)
from pkintel.triage.render import RenderResult


def base_result(score: int = 10, brand: str | None = None) -> TriageResult:
    return TriageResult(is_phish=False, score=score, brand=brand, reasons=["static"], is_live=True)


def ok_render(**kw) -> RenderResult:
    defaults = dict(ok=True, final_url="https://x.test/", status=200)
    defaults.update(kw)
    return RenderResult(**defaults)


# --------------------------------------------------------------------------- hamming
def test_hamming_identical_is_zero():
    assert hamming("ffff", "ffff") == 0


def test_hamming_counts_differing_bits():
    assert hamming("0", "f") == 4  # 0000 vs 1111


def test_hamming_rejects_mismatched_or_empty():
    assert hamming("abcd", "ab") is None
    assert hamming("", "abcd") is None
    assert hamming("zzzz", "abcd") is None  # not hex


# --------------------------------------------------------------------------- screenshot match
def test_screenshot_match_picks_closest_brand():
    refs = [BrandScreenshot("ADCB", "ff00"), BrandScreenshot("Emirates NBD", "ff0f")]
    match = match_brand_screenshot("ff0f", refs, threshold=8)
    assert match == ("Emirates NBD", 0)


def test_screenshot_no_match_beyond_threshold():
    refs = [BrandScreenshot("ADCB", "0000")]
    assert match_brand_screenshot("ffff", refs, threshold=4) is None


def test_screenshot_match_handles_missing_hash():
    assert match_brand_screenshot(None, [BrandScreenshot("ADCB", "ff00")]) is None


# --------------------------------------------------------------------------- deep scoring
def test_failed_render_does_not_change_score():
    """Absence of evidence is not evidence — a dead page keeps its static score."""
    base = base_result(score=30)
    out = deep_score(base, RenderResult(ok=False, error="timeout"))
    assert out.score == 30
    assert out.reasons == base.reasons


def test_base_result_is_not_mutated():
    base = base_result(score=10)
    deep_score(base, ok_render(has_password_field=True, exfil_endpoints=["POST https://evil/x"]))
    assert base.score == 10
    assert base.reasons == ["static"]


def test_observed_offorigin_post_with_password_scores_high():
    # static_had_password_field=True isolates the POST signal; otherwise the
    # js-reveal signal legitimately fires too and the total is 90, not 60.
    out = deep_score(
        base_result(score=10),
        ok_render(has_password_field=True, exfil_endpoints=["POST https://evil.test/save.php"]),
        static_had_password_field=True,
    )
    assert out.score == 60  # 10 + 50
    assert out.is_phish
    assert any("off-origin" in r for r in out.reasons)


def test_post_and_js_reveal_stack():
    """Both signals are independent and both should count."""
    out = deep_score(
        base_result(score=10),
        ok_render(has_password_field=True, exfil_endpoints=["POST https://evil.test/save.php"]),
        static_had_password_field=False,
    )
    assert out.score == 90  # 10 + 50 + 30


def test_offorigin_post_without_password_field_does_not_fire():
    """A CDN POST on a page with no login form is not credential exfil."""
    out = deep_score(
        base_result(score=10),
        ok_render(has_password_field=False, exfil_endpoints=["POST https://analytics.test/x"]),
    )
    assert out.score == 10


def test_known_exfil_channel_fires():
    out = deep_score(
        base_result(score=5),
        ok_render(network_hosts=["api.telegram.org", "cdn.test"]),
    )
    assert out.score == 50  # 5 + 45
    assert any("telegram" in r for r in out.reasons)


def test_js_revealed_password_field_is_the_gap_signal():
    """The static fetch saw no password field; the rendered page has one."""
    out = deep_score(
        base_result(score=5),
        ok_render(has_password_field=True),
        static_had_password_field=False,
    )
    assert out.score == 35  # 5 + 30
    assert any("only after JavaScript" in r for r in out.reasons)


def test_js_reveal_does_not_fire_when_static_already_saw_it():
    out = deep_score(
        base_result(score=5),
        ok_render(has_password_field=True),
        static_had_password_field=True,
    )
    assert out.score == 5


def test_image_only_clone_gets_brand_from_screenshot():
    """No brand text anywhere in the DOM — the screenshot is the only identifier."""
    refs = [BrandScreenshot("Emirates NBD", "abcd")]
    out = deep_score(
        base_result(score=5, brand=None),
        ok_render(screenshot_phash="abcd"),
        brand_references=refs,
    )
    assert out.brand == "Emirates NBD"
    assert out.score == 45  # 5 + 40


def test_screenshot_match_does_not_override_detected_brand():
    refs = [BrandScreenshot("ADCB", "abcd")]
    out = deep_score(
        base_result(score=5, brand="Emirates NBD"),
        ok_render(screenshot_phash="abcd"),
        brand_references=refs,
    )
    assert out.brand == "Emirates NBD"  # text detection wins


def test_cloaking_fires_above_threshold_only():
    r = ok_render()
    hit = deep_score(base_result(score=5), r, cloaking_score=0.9, cloak_threshold=0.35)
    miss = deep_score(base_result(score=5), r, cloaking_score=0.1, cloak_threshold=0.35)
    assert hit.score == 40  # 5 + 35
    assert miss.score == 5


def test_score_is_clamped_to_100():
    refs = [BrandScreenshot("ADCB", "abcd")]
    out = deep_score(
        base_result(score=90),
        ok_render(
            has_password_field=True,
            exfil_endpoints=["POST https://evil.test/x"],
            network_hosts=["api.telegram.org"] + [f"h{i}.test" for i in range(20)],
            screenshot_phash="abcd",
        ),
        brand_references=refs,
        cloaking_score=0.9,
    )
    assert out.score == 100


def test_monotonicity_more_signals_never_lowers_score():
    base = base_result(score=20)
    plain = deep_score(base, ok_render())
    loaded = deep_score(
        base,
        ok_render(has_password_field=True, exfil_endpoints=["POST https://evil.test/x"]),
    )
    assert loaded.score >= plain.score
