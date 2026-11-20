"""The presentation boundary formats declared dates, never source evidence."""
from __future__ import annotations

import pytest

from server.sli.core.messages import localize_presentation, message


@pytest.mark.parametrize("locale,expected", [("ru", "01.01.2026, 00:30"), ("en", "Jan 1, 2026, 12:30 AM")])
def test_presentation_dates_use_locale_and_preserve_raw_params(locale, expected):
    params = {"expiration_utc": "2026-01-01T03:30:00+03:00"}
    envelope = message("reports.v2.ad.computers.v6.security.laps_expired.observed", params)
    row = {"observed": "original", "expiration_utc": params["expiration_utc"], "presentation_messages": {"observed": envelope}}
    localized = localize_presentation(row, locale)
    assert expected in localized["observed"]
    assert localized["expiration_utc"] == params["expiration_utc"]
    assert localized["presentation_messages"]["observed"]["params"] == params
    assert row["observed"] == "original"


@pytest.mark.parametrize("locale,expected", [("ru", "21.10.2026"), ("en", "Oct 21, 2026")])
def test_presentation_calendar_date_uses_same_locale_format(locale, expected):
    result = message("reports.v2.ad.computers.v6.security.unsupported_os.observed", {"operating_system": "Synthetic OS", "support_end_date": "2026-10-21"}, locale=locale)
    assert expected in result["text"]
    assert result["params"]["support_end_date"] == "2026-10-21"


@pytest.mark.parametrize("value", [None, "", "invalid", "2026-02-30T00:00:00Z"])
def test_empty_and_invalid_presentation_dates_are_one_dash(value):
    result = message("reports.v2.ad.computers.v6.security.laps_expired.observed", {"expiration_utc": value}, locale="en")
    assert result["text"] == "Scheduled expiration: —."
    assert result["params"]["expiration_utc"] == value


def test_unrelated_text_is_not_recognized_as_a_date():
    params = {"type": "2026-01-01", "name": "2026-01-02"}
    result = message("reports.v2.ad.computers.v6.security.unsupported_os.observed", {"operating_system": params["type"], "support_end_date": "2026-01-03"}, locale="en")
    assert result["text"].startswith("2026-01-01;")


def test_date_parameter_contract_covers_declared_catalog_fields():
    import json
    import re
    from server.sli.core.messages import CATALOG_DIR, catalog

    declared = json.loads((CATALOG_DIR / "date-params.json").read_text(encoding="utf-8"))
    for locale in ("ru", "en"):
        for code, template in catalog(locale).items():
            for name in re.findall(r"\{(\w+)\}", template):
                if name.endswith(("_date", "_utc")) or name == "local_time":
                    assert name in declared.get(code, {}), (code, name)


@pytest.mark.parametrize("locale,expected", [("ru", "21.10.2026, 14:05"), ("en", "Oct 21, 2026, 2:05 PM")])
def test_last_observation_flows_through_report_response(locale, expected):
    from server.sli.core.messages import response_messages

    params = {"last_logon_utc": "2026-10-21T14:05:00Z", "age_days": 90}
    envelope = message("reports.v2.ad.computers.v6.security.stale_activity.observed", params)
    payload = {"report_key": "ad.computers.v6", "items": [{"reasons": [{"observed": "legacy", "presentation_messages": {"observed": envelope}}]}]}
    actual = response_messages(payload, locale)
    reason = actual["items"][0]["reasons"][0]
    assert expected in reason["observed"]
    assert reason["presentation_messages"]["observed"]["params"] == params
    assert payload["items"][0]["reasons"][0]["observed"] == "legacy"


@pytest.mark.parametrize("locale,expected", [("ru", "21.10.2026, 19:05"), ("en", "Oct 21, 2026, 7:05 PM")])
def test_policy_wall_clock_keeps_its_declared_zone(locale, expected):
    params = {"local_time": "2026-10-21T19:05:00+07:00", "timezone": "Asia/Novosibirsk", "policy_version": 2}
    result = message("workstations.reasons.logon_outside_policy", params, locale=locale)
    assert expected in result["text"]
    assert "Asia/Novosibirsk" in result["text"]
    assert result["params"] == params
