"""with_logons=yes must report an error when the whole-population scan times out, not HTTP 500."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from server.sli.core.database import QueryTimeoutError
from server.sli.reporting.v2.reports import computer_logons
from server.sli.reports import what_where_when_reporting as reporting

INVENTORY = {
    "state": "available", "partial": False,
    "items": [{"entity_id": 1, "object_guid": "11111111-1111-4111-8111-111111111111", "display_name": "WS-A", "dns_host_name": "ws-a"}],
}


def _timeout(*_args, **_kwargs):
    raise QueryTimeoutError("cancelled", timeout_ms=10_000)


def test_with_logons_timeout_degrades_to_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(reporting, "_load_workstation_population", lambda _ids: INVENTORY)
    monkeypatch.setattr(reporting, "_load_projection_status", lambda: {"state": "available", "backfill_completed": True})
    monkeypatch.setattr(reporting, "_load_observation_summaries", _timeout)
    with pytest.raises(reporting.ObservationsUnavailableError):
        reporting.get_computer_logon_computers(
            domain_ids=[7], with_logons=True, from_utc="2026-08-01T00:00:00Z", to_utc_exclusive="2026-09-01T00:00:00Z",
        )

    monkeypatch.setattr(computer_logons, "logon_domain_scope", lambda _access: [7])
    context = SimpleNamespace(
        access={}, limit=50, cursor=None,
        params={"period": {"from_utc": "2026-08-01T00:00:00Z", "to_utc": "2026-09-01T00:00:00Z"}, "with_logons": "yes"},
    )
    out = computer_logons._query(context)
    assert out["state"] == "error"
    assert out["items"] == []
    assert out["limitations"][0]["code"] == "observations_unavailable"
    assert "сузьте период" in out["limitations"][0]["text"]


def test_with_logons_yes_filters_to_computers_with_logons(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(reporting, "_load_workstation_population", lambda _ids: INVENTORY)
    monkeypatch.setattr(reporting, "_load_projection_status", lambda: {"state": "available", "backfill_completed": True})
    monkeypatch.setattr(
        reporting, "_load_observation_summaries",
        lambda *_a, **_k: {"11111111-1111-4111-8111-111111111111": {"login_count": 2, "last_observed_logon_at_utc": None}},
    )
    monkeypatch.setattr(computer_logons, "logon_domain_scope", lambda _access: [7])
    context = SimpleNamespace(
        access={}, limit=50, cursor=None,
        params={"period": {"from_utc": "2026-08-01T00:00:00Z", "to_utc": "2026-09-01T00:00:00Z"}, "with_logons": "yes"},
    )
    out = computer_logons._query(context)
    assert [item["display_name"] for item in out["items"]] == ["WS-A"]
