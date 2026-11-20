from datetime import datetime, timezone

import pytest

from server.sli.reporting import home_trends as trends


def measurement(value=4, **overrides):
    return {"value": value, "scope": {"domain_ids": [7]}, "time_zone": "UTC", "unit": "events",
            "definition_version": 1, "coverage": {"sources": [7], "complete": True},
            "window": {"from_utc": "2026-10-01T00:00:00Z", "to_utc": "2026-10-02T00:00:00Z"}, **overrides}


def previous(value=2, **overrides):
    return measurement(value, **{"window": {"from_utc": "2026-09-30T00:00:00Z", "to_utc": "2026-10-01T00:00:00Z"}, **overrides})


def test_trend_requires_a_baseline_and_uses_absolute_change_for_zero():
    assert trends.compare(measurement(), None)["state"] == "missing"
    assert trends.compare(measurement(), previous(0)) == {
        "state": "comparable", "message_code": "home.comparison.absolute", "absolute_change": 4,
        "percent_change": None, "tone": "neutral"}
    assert trends.compare(measurement(), previous(), meaning="lower_is_better")["tone"] == "danger"
    assert trends.compare(measurement(), previous(), meaning="higher_is_better")["tone"] == "success"


@pytest.mark.parametrize("overrides", [
    {"scope": {"domain_ids": [8]}}, {"time_zone": "Asia/Bangkok"}, {"unit": "accounts"},
    {"definition_version": 2}, {"coverage": {"sources": [8], "complete": True}},
    {"coverage": {}}, {"window": {"from_utc": "2026-09-29T00:00:00Z", "to_utc": "2026-10-01T00:00:00Z"}},
])
def test_changed_measurement_contract_is_incomparable(overrides):
    assert trends.compare(measurement(), previous(**overrides))["state"] == "incomparable"


def test_completed_windows_respect_local_midnight_and_exclusive_custom_bounds():
    now = datetime(2026, 10, 7, 8, 30, tzinfo=timezone.utc)
    current, prior = trends.completed_windows({"period": {"preset": "current"}, "time_zone": "Asia/Bangkok"}, now)
    assert current == {"from_utc": "2026-10-05T17:00:00Z", "to_utc": "2026-10-06T17:00:00Z"}
    assert prior == {"from_utc": "2026-10-04T17:00:00Z", "to_utc": "2026-10-05T17:00:00Z"}
    with pytest.raises(ValueError, match="home_window_incomplete"):
        trends.completed_windows({"period": {"preset": "custom", "from_utc": "2026-10-07T00:00:00Z",
                                           "to_utc": "2026-10-08T00:00:00Z"}, "time_zone": "UTC"}, now)


def test_local_day_comparison_remains_valid_across_dst():
    now = datetime(2026, 3, 9, 12, tzinfo=timezone.utc)
    current, prior = trends.completed_windows({"period": {"preset": "24h"}, "time_zone": "America/New_York"}, now)
    assert current == {"from_utc": "2026-03-08T05:00:00Z", "to_utc": "2026-03-09T04:00:00Z"}
    assert prior == {"from_utc": "2026-03-07T05:00:00Z", "to_utc": "2026-03-08T05:00:00Z"}
    assert trends.compare(measurement(window=current, time_zone="America/New_York"),
                          previous(window=prior, time_zone="America/New_York"))["state"] == "comparable"
