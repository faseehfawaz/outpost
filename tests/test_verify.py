"""Tests for takedown verification (pkintel.takedown.verify).

The bias that matters: a false "dead" closes the case on a *live* phishing site,
which is far worse than an extra probe. So ambiguous evidence must resolve to
"still live" every time.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from pkintel.takedown.verify import ESCALATION_TARGETS, _should_escalate, looks_dead


# --------------------------------------------------------------------------- dead detection
@pytest.mark.parametrize("status", [403, 404, 410, 451])
def test_dead_status_codes(status: int):
    dead, reason = looks_dead(status, "<html>whatever</html>")
    assert dead
    assert reason == f"http_{status}"


def test_unreachable_is_dead():
    dead, reason = looks_dead(None, None)
    assert dead
    assert reason == "unreachable"


@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_5xx_is_ambiguous_not_dead(status: int):
    """A 5xx could be a dead backend or a busy one. Never close the case on it."""
    dead, reason = looks_dead(status, None)
    assert not dead
    assert "ambiguous" in reason


def test_live_phishing_page_is_not_dead():
    body = (
        "<html><body><form><input type=password name=pin></form>" + ("x" * 500) + "</body></html>"
    )
    dead, reason = looks_dead(200, body)
    assert not dead
    assert reason == "still_live"


@pytest.mark.parametrize(
    "marker",
    [
        "Account Suspended",
        "This site has been suspended",
        "reported for phishing",
        "Deceptive site ahead",
        "domain has been seized",
    ],
)
def test_suspension_page_on_200_is_dead(marker: str):
    """Many hosts serve a 200 suspension page rather than a 404."""
    body = f"<html><body><h1>{marker}</h1>{'y' * 400}</body></html>"
    dead, reason = looks_dead(200, body)
    assert dead
    assert reason.startswith("suspension_page:")


def test_empty_200_is_dead():
    dead, reason = looks_dead(200, "<html></html>")
    assert dead
    assert reason == "empty_response"


def test_marker_matching_is_case_insensitive():
    dead, _ = looks_dead(200, "<html>" + "ACCOUNT SUSPENDED" + ("z" * 400) + "</html>")
    assert dead


def test_200_with_no_body_is_not_confidently_dead():
    """No body to inspect (e.g. non-text content type) -> stay conservative."""
    dead, reason = looks_dead(200, None)
    assert not dead
    assert reason == "still_live"


# --------------------------------------------------------------------------- escalation
def now_minus(hours: float) -> datetime:
    return datetime.now(timezone.utc) - timedelta(hours=hours)


def test_no_escalation_before_the_window(monkeypatch):
    from pkintel.config import settings

    monkeypatch.setattr(settings, "takedown_escalate_after_s", 48 * 3600)
    assert not _should_escalate(now_minus(1), 0)
    assert not _should_escalate(now_minus(47), 0)


def test_escalates_after_the_window(monkeypatch):
    from pkintel.config import settings

    monkeypatch.setattr(settings, "takedown_escalate_after_s", 48 * 3600)
    assert _should_escalate(now_minus(49), 0)


def test_each_level_waits_progressively_longer(monkeypatch):
    """Higher authorities are slower by nature, so we wait longer before using them."""
    from pkintel.config import settings

    monkeypatch.setattr(settings, "takedown_escalate_after_s", 24 * 3600)
    # level 0 -> 1 needs 24h; level 1 -> 2 needs 48h
    assert _should_escalate(now_minus(25), 0)
    assert not _should_escalate(now_minus(25), 1)
    assert _should_escalate(now_minus(49), 1)


def test_no_escalation_past_top_of_ladder(monkeypatch):
    from pkintel.config import settings

    monkeypatch.setattr(settings, "takedown_escalate_after_s", 1)
    top = len(ESCALATION_TARGETS) - 1
    assert not _should_escalate(now_minus(10_000), top)


def test_no_escalation_without_sent_at():
    assert not _should_escalate(None, 0)


def test_escalation_ladder_is_ordered_by_increasing_authority():
    assert ESCALATION_TARGETS[0] == "host"
    assert ESCALATION_TARGETS[1] == "registrar"
    assert len(ESCALATION_TARGETS) >= 3
