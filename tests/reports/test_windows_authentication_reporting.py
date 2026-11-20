from __future__ import annotations

from datetime import datetime, timedelta, timezone
from random import Random

import pytest

from server.sli.reports import windows_authentication_reporting as reporting
from server.sli.reports.windows_authentication_reporting import (
    compose_windows_authentication_report,
)


UTC = timezone.utc


def _event(event_db_id: int, event_id: int, minute: int, *, sid: str | None, source_ip: str | None) -> dict:
    return {
        "event_db_id": event_db_id,
        "event_record_id": 9000 + event_db_id,
        "event_id": event_id,
        "time_created_utc": datetime(2026, 8, 21, 10, minute, tzinfo=UTC),
        "domain_controller": "dc-1",
        "target_user_sid": sid,
        "source_ip": source_ip,
        "source_core_sha256": b"a" * 32,
    }


def test_composer_publishes_ordered_native_facts_without_lifecycle_pairing() -> None:
    payload = compose_windows_authentication_report(
        source_domain_id=7,
        period_start=datetime(2026, 8, 21, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 21, 11, tzinfo=UTC),
        events=[
            {
                "event_db_id": 9,
                "event_record_id": 9009,
                "event_id": 4634,
                "time_created_utc": datetime(2026, 8, 21, 10, 2, tzinfo=UTC),
                "domain_controller": "dc-1",
                "target_user_sid": "S-1-5-21-101",
                "target_user_name": "alice",
                "source_ip": "198.51.100.7",
                "source_core_sha256": b"a" * 32,
                "source_facts_sha256": b"b" * 32,
            },
            {
                "event_db_id": 3,
                "event_record_id": 9003,
                "event_id": 4624,
                "time_created_utc": datetime(2026, 8, 21, 10, 1, tzinfo=UTC),
                "domain_controller": "dc-1",
                "target_user_sid": "S-1-5-21-101",
                "target_user_name": "alice",
                "source_ip": "198.51.100.7",
                "source_core_sha256": b"c" * 32,
                "source_facts_sha256": b"d" * 32,
            },
        ],
        collection_coverage={"history_event_present": True},
    )

    assert [item["event_db_id"] for item in payload["items"]] == [3, 9]
    assert payload["items"][1]["authentication_fact"] == "observed_logoff"
    assert payload["items"][0]["evidence"] == {
        "event_db_id": 3,
        "event_record_id": 9003,
        "source_core_sha256": "63" * 32,
        "source_facts_sha256": "64" * 32,
    }
    assert payload["items"][0]["source"] == {
        "state": "observed",
        "source_ip": "198.51.100.7",
    }
    expected_item_keys = {
        "event_db_id", "event_record_id", "event_id", "time_created_utc",
        "domain_controller", "authentication_fact", "target", "principal", "source",
        "source_native", "evidence", "earlier_observed_failures_in_window",
    }
    assert set(payload["items"][0]) == expected_item_keys
    assert set(payload["items"][1]) == expected_item_keys - {
        "earlier_observed_failures_in_window",
    }
    for item in payload["items"]:
        assert item["target"] == {
            "state": "observed",
            "target_user_sid": "S-1-5-21-101",
            "target_user_name": "alice",
        }
        assert item["principal"] == {
            "role": "target_account",
            "state": "observed",
            "principal_user_sid": "S-1-5-21-101",
            "principal_user_name": "alice",
        }
        assert item["source"] == {
            "state": "observed",
            "source_ip": "198.51.100.7",
        }
        assert item["source_native"] == {}
        assert item["evidence"]["event_db_id"] == item["event_db_id"]
        assert item["evidence"]["event_record_id"] == item["event_record_id"]


def test_credential_validation_without_native_result_stays_unknown() -> None:
    payload = compose_windows_authentication_report(
        source_domain_id=7,
        period_start=datetime(2026, 8, 21, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 21, 11, tzinfo=UTC),
        events=[{
            "event_db_id": 77,
            "event_record_id": 9077,
            "event_id": 4776,
            "time_created_utc": datetime(2026, 8, 21, 10, 1, tzinfo=UTC),
            "domain_controller": "dc-1",
            "source_core_sha256": b"a" * 32,
        }],
        collection_coverage={"history_event_present": True},
    )

    assert payload["items"][0]["outcome"] == {"state": "unknown"}
    assert payload["items"][0]["source_native"] == {}


@pytest.mark.parametrize("code, result", [
    ("0xc0000234", "failure"), ("0xC000006A", "failure"), ("0xc0000072", "failure"),
    ("0x0", "success"), ("0x00000000", "success"), (None, None),
])
def test_ntlm_validation_counts_failures_without_source_ip(code, result) -> None:
    payload = compose_windows_authentication_report(
        source_domain_id=7,
        period_start=datetime(2026, 8, 21, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 21, 11, tzinfo=UTC),
        events=[{**_event(77, 4776, 1, sid=None, source_ip=None), "result_code": code}],
        collection_coverage={"history_event_present": True},
    )
    item = payload["items"][0]
    assert item["source"] == {"state": "unknown"}
    assert item["outcome"] == (
        {"state": "observed", "result": result, "result_code": code} if result else {"state": "unknown"}
    )
    assert reporting._is_failure_fact(item) is (result == "failure")


def test_mixed_result_events_use_only_the_saved_source_native_result_code() -> None:
    payload = compose_windows_authentication_report(
        source_domain_id=7,
        period_start=datetime(2026, 8, 21, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 21, 11, tzinfo=UTC),
        events=[
            {**_event(71, 4776, 1, sid="S-1", source_ip="198.51.100.7"), "result_code": "0x0"},
            {**_event(72, 4776, 2, sid="S-2", source_ip="198.51.100.7"), "result_code": "0xC000006D"},
            {
                **_event(73, 4672, 3, sid="target-sid", source_ip=None),
                "subject_user_sid": "subject-sid",
                "subject_user_name": "administrator",
            },
        ],
        collection_coverage={"history_event_present": True},
    )

    assert payload["items"][0]["outcome"] == {
        "state": "observed", "result": "success", "result_code": "0x0"
    }
    assert payload["items"][1]["outcome"] == {
        "state": "observed", "result": "failure", "result_code": "0xC000006D"
    }
    assert payload["items"][2]["principal"] == {
        "role": "subject_account",
        "state": "observed",
        "principal_user_sid": "subject-sid",
        "principal_user_name": "administrator",
    }


def test_policy_uses_only_exact_sid_and_nonempty_source_ip(monkeypatch) -> None:
    events = [
        _event(1, 4625, 1, sid="S-1", source_ip="198.51.100.7"),
        _event(2, 4771, 2, sid="S-2", source_ip="198.51.100.7"),
        {**_event(3, 4776, 3, sid="S-3", source_ip="198.51.100.7"), "result_code": "0xC000006D"},
        _event(4, 4773, 4, sid="S-1", source_ip="198.51.100.7"),
        _event(5, 4625, 5, sid="S-2", source_ip="198.51.100.7"),
        _event(6, 4625, 6, sid=None, source_ip="198.51.100.7"),
        _event(7, 4625, 7, sid="S-4", source_ip=None),
        _event(8, 4624, 9, sid="S-1", source_ip="198.51.100.7"),
        _event(9, 4624, 10, sid=None, source_ip="198.51.100.7"),
    ]

    from server.sli.core.platform_settings import SETTINGS
    monkeypatch.setattr(reporting, "get_setting", lambda key: SETTINGS[key].default)
    policy = reporting._read_manual_review_policy(
        _ReviewCursor(events), datetime(2026, 8, 21, 10, tzinfo=UTC), datetime(2026, 8, 21, 11, tzinfo=UTC), 7,
    )
    payload = compose_windows_authentication_report(
        source_domain_id=7,
        period_start=datetime(2026, 8, 21, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 21, 11, tzinfo=UTC),
        events=events,
        collection_coverage={"history_event_present": True},
        manual_review_policy=policy,
    )

    policy = payload["manual_review_policy"]
    assert policy["state"] == "manual_review_signal"
    assert policy["conditions"] == {
        "minimum_failure_facts": 5,
        "minimum_distinct_target_sids": 3,
        "source_ip": "nonempty_source_native",
        "rolling_window_minutes": 15,
    }
    assert policy["time_bounds"] == {
        "from_utc": "2026-08-21T10:00:00Z",
        "to_utc_exclusive": "2026-08-21T11:00:00Z",
    }
    assert policy["not_a_verdict"] is True
    assert policy["signals"][0] | {"event_references": []} == {
        "state": "manual_review_signal",
        "source_ip": "198.51.100.7",
        "window": {
            "from_utc": "2026-08-21T10:01:00Z",
            "to_utc_exclusive": "2026-08-21T10:16:00Z",
        },
        "failure_fact_count": 5,
        "distinct_target_sid_count": 3,
        "rule": "single_ip",
        "distinct_source_count": 1,
        "evidence_event_db_id": 1,
        "event_references": [],
        "not_a_verdict": True,
    }
    assert policy["signals"][0]["evidence_event_db_id"] == 1
    assert [item["event_db_id"] for item in payload["items"][-2]["earlier_observed_failures_in_window"]["event_references"]] == [1, 4]
    assert payload["items"][-1]["earlier_observed_failures_in_window"]["state"] == "unknown"
    no_signal = compose_windows_authentication_report(
        source_domain_id=7,
        period_start=datetime(2026, 8, 21, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 21, 11, tzinfo=UTC),
        events=[],
        collection_coverage={"history_event_present": True},
        manual_review_policy=reporting._read_manual_review_policy(
            _ReviewCursor([]), datetime(2026, 8, 21, 10, tzinfo=UTC), datetime(2026, 8, 21, 11, tzinfo=UTC), 7,
        ),
    )
    assert no_signal["manual_review_policy"]["state"] == "no_observed_signal_unverified"
    assert no_signal["manual_review_policy"]["conditions"] == policy["conditions"]
    assert no_signal["manual_review_policy"]["not_a_verdict"] is True


def test_4772_is_not_accepted_as_an_observed_windows_authentication_fact() -> None:
    with pytest.raises(ValueError, match="windows_authentication_event_invalid"):
        compose_windows_authentication_report(
            source_domain_id=7,
            period_start=datetime(2026, 8, 21, 10, tzinfo=UTC),
            period_end=datetime(2026, 8, 21, 11, tzinfo=UTC),
            events=[_event(77, 4772, 1, sid="S-1", source_ip="198.51.100.7")],
            collection_coverage={"history_event_present": True},
        )


def test_high_volume_window_returns_a_bounded_prefix_instead_of_an_input_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = [_event(index + 1, 4625, index % 60, sid=f"S-{index}", source_ip="198.51.100.7") for index in range(501)]
    bounded, truncated = reporting._bounded_events(events, 500)
    assert len(bounded) == 500
    assert truncated is True

    monkeypatch.setattr(
        reporting,
        "_read_windows_authentication_data",
        lambda **_kwargs: (bounded, {"history_event_present": True}, {
            "truncated": truncated, "manual_review_policy": {"coverage_scope": "whole_period"},
        }),
    )
    access = {
        "platform_owner": False,
        "capabilities": ["events.view"],
        "capability_policies": [],
        "reports": [{
            "report_key": "vpn.audit",
            "allowed": True,
            "allowed_actions": ["view"],
            "grants": [{"allowed_actions": ["view"], "scope": {"kind": "domain", "ids": [7]}}],
        }],
    }
    payload = reporting.get_windows_authentication_report(
        access, source_domain_id=7,
        time_from="2026-08-21T10:00:00Z", time_to="2026-08-21T11:00:00Z", limit=500,
    )
    assert payload["result_window"] == {
        "display_limit": 500, "returned_event_count": 500, "truncated": True
    }


def test_report_denies_before_database_read_without_events_view(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        reporting,
        "_read_windows_authentication_data",
        lambda **_kwargs: pytest.fail("database must not be read"),
    )
    access = {
        "platform_owner": False,
        "capabilities": [],
        "capability_policies": [],
        "reports": [{
            "report_key": "vpn.audit",
            "allowed": True,
            "allowed_actions": ["view"],
            "grants": [{"allowed_actions": ["view"], "scope": {"kind": "domain", "ids": [7]}}],
        }],
    }

    payload = reporting.get_windows_authentication_report(
        access,
        source_domain_id=7,
        time_from="2026-08-21T10:00:00Z",
        time_to="2026-08-21T11:00:00Z",
    )

    assert payload["state"] == "not_authorized"

    missing_vpn_audit = {
        **access,
        "capabilities": ["events.view"],
        "reports": [{
            "report_key": "vpn.audit",
            "allowed": True,
            "allowed_actions": ["view"],
            "grants": [{"allowed_actions": ["view"], "scope": {"kind": "domain", "ids": [8]}}],
        }],
    }
    assert reporting.get_windows_authentication_report(
        missing_vpn_audit,
        source_domain_id=7,
        time_from="2026-08-21T10:00:00Z",
        time_to="2026-08-21T11:00:00Z",
    )["state"] == "not_authorized"


def test_source_discovery_returns_only_domains_authorized_for_both_boundaries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        reporting,
        "_read_windows_authentication_domain_batch",
        lambda **_kwargs: [7, 8],
    )
    monkeypatch.setattr(
        reporting,
        "_has_windows_authentication_source",
        lambda domain_id: domain_id == 7,
    )
    access = {
        "platform_owner": False,
        "capabilities": ["events.view"],
        "capability_policies": [],
        "reports": [{
            "report_key": "vpn.audit",
            "allowed": True,
            "allowed_actions": ["view"],
            "grants": [{"allowed_actions": ["view"], "scope": {"kind": "domain", "ids": [7]}}],
        }],
    }

    payload = reporting.get_windows_authentication_sources(access)

    assert payload["items"] == [{"source_domain_id": 7}]


def test_source_discovery_denial_never_queries_event_data(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        reporting,
        "_read_windows_authentication_domain_batch",
        lambda **_kwargs: [7],
    )
    monkeypatch.setattr(
        reporting,
        "_has_windows_authentication_source",
        lambda _domain_id: pytest.fail("event data must not be read"),
    )

    missing_both = {
        "platform_owner": False,
        "capabilities": [],
        "capability_policies": [],
        "reports": [],
    }
    missing_events_view = {
        **missing_both,
        "reports": [{
            "report_key": "vpn.audit",
            "allowed": True,
            "allowed_actions": ["view"],
            "grants": [{"allowed_actions": ["view"], "scope": {"kind": "domain", "ids": [7]}}],
        }],
    }
    missing_vpn_audit = {**missing_both, "capabilities": ["events.view"]}

    for access in (missing_both, missing_events_view, missing_vpn_audit):
        assert reporting.get_windows_authentication_sources(access)["state"] == "not_authorized"


def _grid_access(*, capabilities: list[str], domain_id: int = 7) -> dict:
    return {
        "platform_owner": False,
        "capabilities": capabilities,
        "capability_policies": [],
        "reports": [{
            "report_key": "vpn.audit",
            "allowed": True,
            "allowed_actions": ["view"],
            "grants": [{"allowed_actions": ["view"], "scope": {"kind": "domain", "ids": [domain_id]}}],
        }],
    }


class _GridCursor:
    def __init__(self, rows: list[dict]) -> None:
        self.rows, self.statements = rows, []

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=()):
        self.statements.append((" ".join(str(sql).split()), tuple(params)))

    def fetchall(self):
        return self.rows


class _GridConnection:
    def __init__(self, cursor: _GridCursor) -> None:
        self._cursor = cursor

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def cursor(self):
        return self._cursor


def test_failure_grid_counts_the_whole_window_with_the_report_failure_semantics(monkeypatch: pytest.MonkeyPatch) -> None:
    cursor = _GridCursor([{"isodow": 4, "hour": 21, "failures": 3}])
    monkeypatch.setattr(reporting, "_connect", lambda: _GridConnection(cursor))

    grid = reporting.get_windows_authentication_failure_grid(
        _grid_access(capabilities=["events.view"]), source_domain_id=7,
        time_from="2026-09-01T00:00:00Z", time_to="2026-10-01T00:00:00Z", timezone_name="Asia/Novosibirsk",
    )

    assert grid == {"state": "available", "timezone": "Asia/Novosibirsk", "cells": [{"isodow": 4, "hour": 21, "failures": 3}]}
    sql, params = cursor.statements[-1]
    assert "extract(isodow from (event.time_created_utc at time zone %s))" in sql
    assert "group by 1, 2" in sql and " limit " not in sql
    assert params[:3] == ("Asia/Novosibirsk", "Asia/Novosibirsk", 7)
    assert params[-3] == sorted(reporting.WINDOWS_AUTHENTICATION_REPORT_FAILURE_EVENT_IDS)
    assert params[-2] == sorted(reporting.WINDOWS_AUTHENTICATION_REPORT_MIXED_RESULT_EVENT_IDS)
    assert set(params[-1]) == set(reporting._ZERO_RESULT_CODES)


def test_failure_grid_denies_without_events_view_and_rejects_bad_zones(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(reporting, "_connect", lambda: pytest.fail("database must not be read"))
    denied = reporting.get_windows_authentication_failure_grid(
        _grid_access(capabilities=[]), source_domain_id=7,
        time_from="2026-09-01T00:00:00Z", time_to="2026-09-02T00:00:00Z",
    )
    assert denied == {"state": "not_authorized", "cells": []}
    with pytest.raises((ValueError, reporting.TimeRangeError), match="timezone"):
        reporting.get_windows_authentication_failure_grid(
            _grid_access(capabilities=["events.view"]), source_domain_id=7,
            time_from="2026-09-01T00:00:00Z", time_to="2026-09-02T00:00:00Z", timezone_name="Mars/Olympus",
        )


class _ReviewCursor(_GridCursor):
    """Return source facts, leaving window evaluation to the real reader."""

    def execute(self, sql, params=()):
        super().execute(sql, params)
        self.sql, self.params = self.statements[-1]

    def fetchone(self):
        return {"history_event_present": True}

    def fetchall(self):
        if "as sid" not in self.sql:
            return sorted(self.rows, key=lambda row: (row["time_created_utc"], row["event_db_id"]))[:self.params[-1]]
        p = self.params
        failures = [{
            "id": row["event_db_id"], "at": row["time_created_utc"],
            "sid": (row.get("target_user_sid") or "").strip(" "),
            "ip": (row.get("source_ip") or "").strip(" ") or None, "source": self._source(row),
        } for row in self.rows if p[3] <= row["time_created_utc"] < p[4]
            and (row.get("target_user_sid") or "").strip(" ") and (row["event_id"] in p[5]
            or row["event_id"] in p[6] and str(row.get("result_code") or "").strip(" ").lower()
            not in {"", *p[7]})]
        return sorted(failures, key=lambda row: (row["at"], row["id"]))

    @staticmethod
    def _source(row):
        ip = (row.get("source_ip") or "").strip(" ")
        host = (row.get("workstation_name") or "").strip(" ").lower()
        return "ip:" + ip if ip else "host:" + host if host else None


def _whole_period_report(monkeypatch, attack_events, display_limit=200):
    start = datetime(2026, 8, 21, tzinfo=UTC)
    prefix = [{**_event(i + 1, 4624, 0, sid="synthetic-noise", source_ip="198.51.100.1"),
               "time_created_utc": start + timedelta(seconds=i)} for i in range(200)]
    cursor = _ReviewCursor(prefix + attack_events)
    monkeypatch.setattr(reporting, "_connect", lambda: _GridConnection(cursor))
    from server.sli.core.platform_settings import SETTINGS
    monkeypatch.setattr(reporting, "get_setting", lambda key: SETTINGS[key].default)
    report = reporting.get_windows_authentication_report(
        _grid_access(capabilities=["events.view"]), source_domain_id=7,
        time_from="2026-08-21T00:00:00Z", time_to="2026-08-23T00:00:00Z",
        limit=display_limit,
    )
    return report, cursor


def test_whole_period_single_ip_signal_is_independent_of_first_200_events(monkeypatch):
    events = [_event(201 + i, 4625, i, sid=f"synthetic-sid-{i % 3}", source_ip="198.51.100.7") for i in range(5)]
    report, cursor = _whole_period_report(monkeypatch, events)
    policy = report["manual_review_policy"]
    assert policy["coverage_scope"] == "whole_period"
    assert policy["signals"][0]["rule"] == "single_ip"
    assert policy["signals"][0]["failure_fact_count"] == 5
    assert policy["signals"][0]["evidence_event_db_id"] == 201
    assert policy["signals"][0]["not_a_verdict"] is True
    assert report["result_window"] == {"display_limit": 200, "returned_event_count": 200, "truncated": True}
    assert all(item["event_id"] == 4624 for item in report["items"])
    sql, params = cursor.statements[-1]
    assert "where event.domain_id=%s and server.role='domain_controller'" in sql
    assert "event.time_created_utc>=%s and event.time_created_utc<%s" in sql
    assert "nullif(lower(trim(facts.result_code)),'') is not null" in sql
    assert "lower(trim(facts.result_code))<>all(%s)" in sql
    assert "limit %s" in sql  # excess input must remain explicitly unevaluated
    assert params[-1] == reporting.MAX_REVIEW_INPUT_ROWS + 1
    assert "order by event.time_created_utc, event.id" in sql
    assert "join failures" not in sql
    assert params[3:5] == (datetime(2026, 8, 21, tzinfo=UTC), datetime(2026, 8, 23, tzinfo=UTC))


def test_distributed_low_and_slow_detected_outside_sample_across_hour_boundaries(monkeypatch):
    start = datetime(2026, 8, 21, 23, 30, tzinfo=UTC)
    events = [{**_event(201 + i, 4625, 0, sid=f"synthetic-sid-{i}", source_ip=f"198.51.100.{10 + i % 5}"),
               "time_created_utc": start + timedelta(hours=i * 2)} for i in range(10)]
    report, cursor = _whole_period_report(monkeypatch, events)
    policy = report["manual_review_policy"]
    assert len(policy["signals"]) == 1
    signal = policy["signals"][0]
    assert signal["rule"] == "distributed"
    assert (signal["failure_fact_count"], signal["distinct_target_sid_count"], signal["distinct_source_count"]) == (10, 10, 5)
    assert signal["window"] == {"from_utc": "2026-08-21T23:30:00Z", "to_utc_exclusive": "2026-08-22T23:30:00Z"}
    assert report["items"][-1]["event_db_id"] == 200
    assert "'host:' || nullif(lower(trim(event.workstation_name)),''))" in cursor.sql


@pytest.mark.parametrize("kind", ["too_few_accounts", "too_few_sources", "high_volume", "unknown_result", "success"])
def test_whole_period_benign_noise_is_not_a_distributed_signal(monkeypatch, kind):
    events = []
    for i in range(40):
        row = _event(201 + i, 4625, i, sid=f"synthetic-sid-{i % 10}", source_ip=f"198.51.100.{10 + i % 5}")
        if kind == "too_few_accounts":
            row["target_user_sid"] = "synthetic-single-sid"
        elif kind == "too_few_sources":
            row["source_ip"] = None
        elif kind in {"unknown_result", "success"}:
            row["event_id"] = 4776
            row["result_code"] = None if kind == "unknown_result" else "0x0"
        elif kind == "high_volume":
            row["target_user_sid"] = f"synthetic-sid-{i // 4}"
        events.append(row)
    report, _cursor = _whole_period_report(monkeypatch, events)
    assert not any(signal["rule"] == "distributed" for signal in report["manual_review_policy"]["signals"])
    if kind != "high_volume":
        assert report["manual_review_policy"]["signals"] == []
        assert report["manual_review_policy"]["state"] == "no_observed_signal_unverified"
    assert report["collection_coverage"]["source_completeness"] == "not_proven"


def test_distributed_host_fallback_and_configurable_window(monkeypatch):
    events = [{**_event(201 + i, 4625, i, sid=f"synthetic-sid-{i}", source_ip=None),
               "workstation_name": f"synthetic-host-{i % 5}"} for i in range(10)]
    report, _cursor = _whole_period_report(monkeypatch, events)
    assert report["manual_review_policy"]["signals"][0]["distinct_source_count"] == 5
    monkeypatch.setattr(reporting, "get_setting", lambda key: {
        "windows_auth.distributed_window_hours": "1", "windows_auth.distributed_min_accounts": "11",
        "windows_auth.distributed_min_sources": "5", "windows_auth.distributed_max_failures_per_account": "3",
    }[key])
    cursor = _ReviewCursor(events)
    policy = reporting._read_manual_review_policy(cursor, datetime(2026, 8, 21, tzinfo=UTC),
                                                datetime(2026, 8, 23, tzinfo=UTC), 7)
    assert policy["signals"] == []
    assert policy["distributed_conditions"]["rolling_window_hours"] == 1


def test_display_limit_does_not_change_period_signal_counts(monkeypatch):
    events = [_event(201 + i, 4625, i, sid=f"synthetic-sid-{i % 3}", source_ip="198.51.100.7") for i in range(5)]
    reports = [_whole_period_report(monkeypatch, events, limit)[0] for limit in (1, 200, 500)]
    assert [len(report["items"]) for report in reports] == [1, 200, 205]
    assert [report["result_window"]["truncated"] for report in reports] == [True, True, False]
    assert reports[0]["manual_review_policy"] == reports[1]["manual_review_policy"] == reports[2]["manual_review_policy"]


def test_composer_does_not_substitute_a_sample_signal_for_missing_period_analysis():
    payload = compose_windows_authentication_report(
        source_domain_id=7, period_start=datetime(2026, 8, 21, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 21, 11, tzinfo=UTC),
        events=[_event(i + 1, 4625, i, sid=f"synthetic-sid-{i % 3}", source_ip="198.51.100.7") for i in range(5)],
        collection_coverage={"history_event_present": True}, truncated=True,
    )
    assert "manual_review_policy" not in payload
    assert "earlier_failure_context_displayed_sample_only" in payload["limitations"]


def test_signal_list_truncation_does_not_truncate_the_aggregate_input(monkeypatch):
    events = [_event(201 + ip * 5 + minute, 4625, minute, sid=f"synthetic-sid-{minute % 3}",
                     source_ip=f"198.51.100.{ip + 10}") for ip in range(105) for minute in range(5)]
    report, cursor = _whole_period_report(monkeypatch, events)
    policy = report["manual_review_policy"]
    assert len(policy["signals"]) == policy["signal_limit"] == 100
    assert policy["signals_truncated"] is True
    assert policy["coverage_scope"] == "whole_period"
    assert policy["state"] == "manual_review_signal"
    assert "limit %s" in cursor.sql
    assert any("set local statement_timeout = '10000ms'" in sql for sql, _params in cursor.statements)
    expected = _reference_manual_review_signals(cursor.fetchall(), policy, datetime(2026, 8, 23, tzinfo=UTC))
    assert policy["signals"] == expected[:100]
    assert policy["signals_truncated"] == (len(expected) > 100)


def _reference_manual_review_signals(failures, policy, period_end):
    """Small exhaustive oracle for the original forward-window SQL contract."""
    signals = []
    distributed = policy["distributed_conditions"]
    for rule in ("single_ip", "distributed"):
        duration = timedelta(minutes=15) if rule == "single_ip" else timedelta(hours=distributed["rolling_window_hours"])
        if rule == "single_ip":
            anchors = sorted({(row["ip"], row["at"]) for row in failures if row["ip"] is not None})
        else:
            anchors = sorted({("", row["at"]) for row in failures if row["source"] is not None})
        matched = set()
        for ip, at in anchors:
            if ip in matched:
                continue
            window = [row for row in failures if at <= row["at"] < at + duration
                      and (rule == "distributed" or row["ip"] == ip)]
            if rule == "distributed":
                eligible = {sid for sid in {row["sid"] for row in window}
                            if sum(row["sid"] == sid for row in window) <= distributed["maximum_failures_per_target"]}
                window = [row for row in window if row["sid"] in eligible and row["source"] is not None]
            targets = len({row["sid"] for row in window})
            sources = len({row["source"] for row in window})
            if rule == "single_ip":
                qualifies = len(window) >= 5 and targets >= 3
            else:
                qualifies = (targets >= distributed["minimum_distinct_target_sids"]
                             and sources >= distributed["minimum_distinct_sources"])
            if not qualifies:
                continue
            matched.add(ip)
            signals.append({
                "state": "manual_review_signal", "rule": rule,
                "source_ip": ip if rule == "single_ip" else None,
                "window": {"from_utc": reporting._iso(at), "to_utc_exclusive": reporting._iso(min(at + duration, period_end))},
                "failure_fact_count": len(window), "distinct_target_sid_count": targets,
                "distinct_source_count": sources, "event_references": [],
                "evidence_event_db_id": min(row["id"] for row in window), "not_a_verdict": True,
            })
    return sorted(signals, key=lambda row: (
        row["rule"], datetime.fromisoformat(row["window"]["from_utc"].replace("Z", "+00:00")), row["source_ip"] or ""))


def _assert_manual_review_matches_reference(monkeypatch, events, *, hours=1, accounts=3, sources=2, maximum=3):
    monkeypatch.setattr(reporting, "get_setting", lambda key: {
        "windows_auth.distributed_window_hours": hours,
        "windows_auth.distributed_min_accounts": accounts,
        "windows_auth.distributed_min_sources": sources,
        "windows_auth.distributed_max_failures_per_account": maximum,
    }[key])
    start, end = datetime(2026, 8, 21, tzinfo=UTC), datetime(2026, 8, 22, tzinfo=UTC)
    cursor = _ReviewCursor(events)
    policy = reporting._read_manual_review_policy(cursor, start, end, 7)
    expected = _reference_manual_review_signals(cursor.fetchall(), policy, end)
    assert policy["signals"] == expected[:reporting.MAX_REVIEW_SIGNALS]
    assert policy["signals_truncated"] == (len(expected) > reporting.MAX_REVIEW_SIGNALS)
    assert policy["state"] == ("manual_review_signal" if expected else "no_observed_signal_unverified")
    return policy


@pytest.mark.parametrize("seed", range(20))
def test_manual_review_matches_exhaustive_forward_window_contract(monkeypatch, seed):
    random = Random(seed)
    start = datetime(2026, 8, 21, tzinfo=UTC)
    events = []
    for i in range(160):
        row = _event(1000 - i, random.choice([4625, 4771, 4773, 4776, 4768, 4624]), 0,
                     sid=random.choice([None, " ", *[f"synthetic-sid-{j}" for j in range(10)]]),
                     source_ip=random.choice([None, " ", "198.51.100.1", "198.51.100.2", " 198.51.100.3 "]))
        row.update(time_created_utc=start + timedelta(minutes=random.randrange(-1, 240)),
                   result_code=random.choice([None, " ", "0x0", "0x00000000", "0", "00000000", " 0xC000006D "]),
                   workstation_name=random.choice([None, " ", " Synthetic-Host-1 ", "synthetic-host-1", "synthetic-host-2"]))
        events.append(row)
    random.shuffle(events)
    _assert_manual_review_matches_reference(monkeypatch, events)


@pytest.mark.parametrize("rule, duration", [("single_ip", timedelta(minutes=15)), ("distributed", timedelta(hours=1))])
def test_manual_review_uses_first_matching_exclusive_window_and_minimum_evidence(monkeypatch, rule, duration):
    start = datetime(2026, 8, 21, 22, tzinfo=UTC)
    ips = ["198.51.100.1"] * 6 if rule == "single_ip" else [f"198.51.100.{i % 2 + 1}" for i in range(6)]
    times = [start, start + timedelta(microseconds=1), start + duration - timedelta(microseconds=1),
             start + duration - timedelta(microseconds=1), start + duration, start + duration]
    events = [{**_event(9 - i, 4625, 0, sid=f"synthetic-sid-{i // 2}", source_ip=ips[i]),
               "time_created_utc": times[i]} for i in range(6)]
    policy = _assert_manual_review_matches_reference(monkeypatch, events, accounts=3 if rule == "distributed" else 10)
    signal = next(signal for signal in policy["signals"] if signal["rule"] == rule)
    assert signal["window"] == {"from_utc": reporting._iso(times[1]),
                                "to_utc_exclusive": reporting._iso(times[1] + duration)}
    assert signal["failure_fact_count"] == 5
    assert signal["evidence_event_db_id"] == 4


def test_distributed_sourceless_failures_exclude_account_until_cap_recovers(monkeypatch):
    start = datetime(2026, 8, 21, tzinfo=UTC)
    events = [{**_event(50 + i, 4625, 0, sid="synthetic-sid-0", source_ip=None),
               "time_created_utc": start} for i in range(3)]
    events += [{**_event(10 + i, 4625, 0, sid=f"synthetic-sid-{i}", source_ip=f"198.51.100.{i + 1}"),
                "time_created_utc": start + timedelta(minutes=30)} for i in range(3)]
    events += [{**_event(20, 4625, 0, sid="synthetic-sid-1", source_ip="198.51.100.2"),
                "time_created_utc": start + timedelta(minutes=60)}]
    policy = _assert_manual_review_matches_reference(monkeypatch, events)
    signal = policy["signals"][0]
    assert signal["rule"] == "distributed"
    assert signal["window"]["from_utc"] == "2026-08-21T00:30:00Z"
    assert (signal["failure_fact_count"], signal["distinct_target_sid_count"], signal["distinct_source_count"]) == (4, 3, 3)
    assert signal["evidence_event_db_id"] == 10


def test_distributed_does_not_anchor_on_a_sourceless_failure(monkeypatch):
    start = datetime(2026, 8, 21, tzinfo=UTC)
    events = [{**_event(1, 4625, 0, sid="synthetic-unknown-source", source_ip=None), "time_created_utc": start}]
    events += [{**_event(10 + i, 4625, 0, sid=f"synthetic-sid-{i}", source_ip=f"198.51.100.{i + 1}"),
                "time_created_utc": start + timedelta(minutes=10)} for i in range(3)]
    policy = _assert_manual_review_matches_reference(monkeypatch, events)
    assert policy["signals"][0]["window"]["from_utc"] == "2026-08-21T00:10:00Z"


@pytest.mark.parametrize("rule", ["single_ip", "distributed"])
def test_manual_review_clips_window_to_period_and_excludes_end_facts(monkeypatch, rule):
    end = datetime(2026, 8, 22, tzinfo=UTC)
    start = end - timedelta(minutes=5)
    events = [{**_event(20 + i, 4625, 0, sid=f"synthetic-sid-{i % 3}",
                       source_ip="198.51.100.1" if rule == "single_ip" else f"198.51.100.{i % 2 + 1}"),
               "time_created_utc": start} for i in range(5)]
    # This lower evidence ID is outside the half-open input period.
    events += [{**_event(1, 4625, 0, sid="synthetic-outside-period", source_ip="198.51.100.1"),
                "time_created_utc": end}]
    policy = _assert_manual_review_matches_reference(monkeypatch, events, accounts=3 if rule == "distributed" else 10)
    signal = next(signal for signal in policy["signals"] if signal["rule"] == rule)
    assert signal["window"] == {"from_utc": "2026-08-21T23:55:00Z", "to_utc_exclusive": "2026-08-22T00:00:00Z"}
    assert signal["failure_fact_count"] == 5
    assert signal["evidence_event_db_id"] == 20


def test_manual_review_dense_negative_period_has_linear_window_updates(monkeypatch):
    start = datetime(2026, 8, 21, tzinfo=UTC)
    events = [{**_event(i + 201, 4625, 0, sid="synthetic-single-sid", source_ip="198.51.100.1"),
               "time_created_utc": start + timedelta(milliseconds=i)} for i in range(5000)]
    calls = 0
    original = reporting._ManualReviewWindow.change

    def counted(self, row, delta):
        nonlocal calls
        calls += 1
        return original(self, row, delta)

    monkeypatch.setattr(reporting._ManualReviewWindow, "change", counted)
    report, _cursor = _whole_period_report(monkeypatch, events)
    assert report["manual_review_policy"]["state"] == "no_observed_signal_unverified"
    assert report["manual_review_policy"]["signals"] == []
    assert 0 < calls <= 4 * len(events)  # work grows with facts, not overlapping pairs
