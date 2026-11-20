from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json

import pytest

from scripts.maintenance import stage9_g11a3_probe_launcher as launcher
from scripts.maintenance.stage9_g11a3_probe_orchestrator import (
    AccountingObservation,
    AdVpnRecord,
    NpsObservation,
)
UTC = timezone.utc


class _Cursor:
    def __init__(
        self,
        events: list[str],
        rows: tuple[tuple[object, ...], ...],
        *,
        fail_on_function_query: bool = False,
    ) -> None:
        self._events = events
        self._rows = rows
        self._fail_on_function_query = fail_on_function_query

    def __enter__(self) -> _Cursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, query: str) -> None:
        self._events.append("database_query:" + " ".join(query.split()))
        if (
            self._fail_on_function_query
            and "sli_g11a3_preflight_state_v1" in query
        ):
            raise PermissionError("secret function detail")

    def fetchmany(self, size: int) -> list[tuple[object, ...]]:
        return list(self._rows[:size])


class _Transaction:
    def __enter__(self) -> _Transaction:
        return self

    def __exit__(self, *_args: object) -> None:
        return None


class _Connection:
    def __init__(
        self,
        events: list[str],
        rows: tuple[tuple[object, ...], ...] = ((True, True, True, 0),),
        *,
        result_sets: tuple[tuple[tuple[object, ...], ...], ...] = (),
        fail_on_function_query: bool = False,
    ) -> None:
        self._events = events
        self._rows = rows
        self._result_sets = result_sets
        self._cursor_index = 0
        self._fail_on_function_query = fail_on_function_query

    def transaction(self) -> _Transaction:
        return _Transaction()

    def cursor(self) -> _Cursor:
        rows = self._rows
        if self._result_sets:
            rows = self._result_sets[
                min(self._cursor_index, len(self._result_sets) - 1)
            ]
            self._cursor_index += 1
        return _Cursor(
            self._events,
            rows,
            fail_on_function_query=self._fail_on_function_query,
        )


class _Sources:
    def __init__(
        self,
        events: list[str],
        *,
        nps_cap: bool = False,
        accounting_cap: bool = False,
    ) -> None:
        self.events = events
        self.nps_cap = nps_cap
        self.accounting_cap = accounting_cap
        observed = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)
        self.nps = (
            NpsObservation(
                event_id=6272,
                observed_at_utc=observed,
                record_id="fixture-nps",
                subject_sid="S-1-fixture",
                account_session_id="different-nps-session",
                nas_identity="different-nps-nas",
            ),
        )
        self.accounting = (
            AccountingObservation(
                packet_type="access_accept",
                observed_at_utc=observed,
                class_attribute="fixture-class",
                account_session_id="different-access-accept-session",
                nas_identity="different-access-accept-nas",
                canonical_record_sha256="a" * 64,
                principal_observation="example.test/Users/fixture-user",
            ),
            AccountingObservation(
                packet_type="start",
                observed_at_utc=observed + timedelta(seconds=5),
                class_attribute="fixture-class",
                account_session_id="fixture-session",
                nas_identity="fixture-nas",
                canonical_record_sha256="b" * 64,
            ),
            AccountingObservation(
                packet_type="stop",
                observed_at_utc=observed + timedelta(minutes=2),
                class_attribute="fixture-class",
                account_session_id="fixture-session",
                nas_identity="fixture-nas",
                canonical_record_sha256="c" * 64,
            ),
        )

    def collect_nps(self, limits: launcher.ProbeCollectionLimits) -> launcher.NpsBatch:
        self.events.append(
            "nps:"
            f"{limits.window_start_utc.isoformat()}/"
            f"{limits.window_end_utc.isoformat()}/"
            f"{limits.nps_events}"
        )
        observations = self.nps
        if self.nps_cap:
            observations = tuple(self.nps[0] for _ in range(limits.nps_events + 1))
        return launcher.NpsBatch(observations, cap_reached=self.nps_cap)

    def collect_accounting(
        self, limits: launcher.ProbeCollectionLimits
    ) -> launcher.AccountingBatch:
        self.events.append(
            "accounting:"
            f"{limits.accounting_files}/{limits.accounting_records}/"
            f"{limits.accounting_bytes}/{limits.accounting_candidates}"
        )
        return launcher.AccountingBatch(
            self.accounting,
            files_read=1,
            bytes_read=1024,
            candidates_seen=1,
            candidate_cap_reached=self.accounting_cap,
        )

    def lookup_ad(self, principal_observation: str) -> tuple[AdVpnRecord, ...]:
        self.events.append("ad")
        return (
            AdVpnRecord(
                subject_sid="S-1-fixture",
                immutable_object_id="fixture-object",
                enabled=True,
                object_class="user",
                vpn_member=True,
                lookup_principal_observation=principal_observation,
            ),
        )


def _identity(**_kwargs: str | None) -> dict[str, object]:
    return {
        "status": "ok",
        "current_principal": r"EXAMPLE\operator",
        "expected_principal": r"EXAMPLE\operator",
        "interactive": True,
        "elevated": False,
    }


def _function_row(*, cursor_revision: int = 0) -> tuple[bool, bool, bool, int]:
    return True, True, True, cursor_revision


def test_preflight_diagnosis_stops_before_database_on_identity_failure(
    monkeypatch,
) -> None:
    events: list[str] = []
    identity = {
        "status": "failed",
        "reasons": ["expected_principal_missing", "sid_mismatch"],
        "current_principal": r"OTHER\attacker",
        "expected_principal": "",
        "interactive": False,
        "elevated": False,
    }
    monkeypatch.setattr(
        launcher,
        "verify_collection_identity",
        lambda: events.append("identity") or identity,
    )
    diagnosis = launcher.inspect_probe_preflight(_Connection(events))

    assert diagnosis.identity_check == "failed"
    assert diagnosis.identity_failure_reasons == (
        "expected_principal_missing",
        "sid_mismatch",
    )
    assert diagnosis.database_check == "not_run"
    assert diagnosis.database_error_type is None
    assert diagnosis.database_failure_stage is None
    assert diagnosis.preflight is None
    assert events == ["identity"]


def test_preflight_diagnosis_fails_closed_when_identity_check_raises(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        launcher,
        "verify_collection_identity",
        lambda: (_ for _ in ()).throw(RuntimeError("secret")),
    )

    diagnosis = launcher.inspect_probe_preflight(
        _Connection([])
    )

    assert diagnosis.identity_check == "failed"
    assert diagnosis.identity_failure_reasons == ("identity_check_failed",)
    assert diagnosis.database_check == "not_run"
    assert diagnosis.preflight is None


def test_preflight_diagnosis_reports_safe_function_error_type(
    monkeypatch,
) -> None:
    monkeypatch.setattr(launcher, "verify_collection_identity", _identity)

    diagnosis = launcher.inspect_probe_preflight(
        _Connection([], fail_on_function_query=True)
    )

    assert diagnosis.identity_check == "passed"
    assert diagnosis.identity_failure_reasons == ()
    assert diagnosis.database_check == "failed"
    assert diagnosis.database_error_type == "PermissionError"
    assert diagnosis.database_failure_stage == "preflight_function"
    assert diagnosis.preflight is None
    assert "secret function detail" not in repr(diagnosis)


def test_identity_recheck_uses_the_protected_principal_and_sid(
    monkeypatch,
) -> None:
    observed: dict[str, str] = {}

    def _verify(**kwargs: str) -> dict[str, object]:
        observed.update(kwargs)
        return _identity()

    monkeypatch.setattr(launcher, "verify_collection_identity", _verify)

    ok, reasons = launcher.inspect_probe_identity(
        approved_identity=r"EXAMPLE\operator",
        approved_sid="S-1-5-21-100000001-200000001-300000001-1000",
    )

    assert ok is True
    assert reasons == ()
    assert observed == {
        "expected_principal": r"EXAMPLE\operator",
        "expected_sid": "S-1-5-21-100000001-200000001-300000001-1000",
    }


def test_preflight_uses_one_execute_only_function_call(
    monkeypatch,
) -> None:
    events: list[str] = []
    monkeypatch.setattr(launcher, "verify_collection_identity", _identity)

    diagnosis = launcher.inspect_probe_preflight(
        _Connection(events, ((_function_row(cursor_revision=3)),))
    )

    assert diagnosis.identity_check == "passed"
    assert diagnosis.database_check == "passed"
    assert diagnosis.cursor_revision == 3
    assert events == [
        "database_query:set transaction read only",
        (
            "database_query:select source_subscription_disabled,"
            "no_temporary_login, no_worker_started,cursor_revision from "
            "public.sli_g11a3_preflight_state_v1()"
        ),
    ]


@pytest.mark.parametrize(
    "rows",
    [
        (),
        (_function_row(), _function_row()),
        ((1, True, True, 0),),
        ((True, True, True, True),),
        ((True, True, True, "0"),),
        ((True, True, True, -1),),
    ],
)
def test_preflight_rejects_zero_two_or_malformed_function_rows(
    monkeypatch, rows: tuple[tuple[object, ...], ...]
) -> None:
    monkeypatch.setattr(launcher, "verify_collection_identity", _identity)

    diagnosis = launcher.inspect_probe_preflight(_Connection([], rows))

    assert diagnosis.database_check == "failed"
    assert diagnosis.database_error_type == "PreflightStateError"
    assert diagnosis.database_failure_stage == "preflight_function"
    assert diagnosis.preflight is None


def test_preflight_diagnosis_distinguishes_unsafe_state_from_database_failure(
    monkeypatch,
) -> None:
    monkeypatch.setattr(launcher, "verify_collection_identity", _identity)

    diagnosis = launcher.inspect_probe_preflight(
        _Connection([], ((True, False, False, 0),))
    )

    assert diagnosis.identity_check == "passed"
    assert diagnosis.database_check == "passed"
    assert diagnosis.database_error_type is None
    assert diagnosis.database_failure_stage is None
    assert diagnosis.cursor_revision == 0
    assert diagnosis.cursor_check == "baseline_recorded"
    assert diagnosis.preflight.no_temporary_login is False
    assert diagnosis.preflight.no_worker_started is False


def test_launcher_proves_preflight_before_collecting_and_returns_redacted_result(
    monkeypatch,
) -> None:
    events: list[str] = []
    sources = _Sources(events)
    monkeypatch.setattr(
        launcher,
        "verify_collection_identity",
        lambda **kwargs: events.append("identity") or _identity(**kwargs),
    )
    result = launcher.launch_probe(
        _Connection(events),
        sources,
        approved_identity=r"EXAMPLE\operator",
        approved_sid="S-1-5-21-100000001-200000001-300000001-1000",
    )

    assert result["terminal_quality_state"] == "proven"
    assert events[:3] == [
        "identity",
        "database_query:set transaction read only",
        events[2],
    ]
    assert "sli_g11a3_preflight_state_v1" in events[2]
    assert "pg_roles" not in events[2]
    assert "pg_stat_activity" not in events[2]
    assert events[3:] == [
        "accounting:1/400/262144/20",
        (
            "nps:2026-08-11T11:50:00+00:00/"
            "2026-08-11T12:10:00+00:00/500"
        ),
        "ad",
        "identity",
        "database_query:set transaction read only",
        events[8],
    ]
    assert "sli_g11a3_preflight_state_v1" in events[8]
    assert result["postflight_attestation"] == {
        "performed": True,
        "identity_reverified": True,
        "database_rechecked": True,
        "cursor_unchanged": True,
    }
    assert set(result) == {
        "plan_id",
        "source_contract_ids",
        "counts",
        "cap_and_timeout_flags",
        "provenance_digests",
            "exact_link_bools",
            "terminal_quality_state",
            "stop_reason",
            "postflight_attestation",
        }
    assert result["stop_reason"] == "none"
    encoded = json.dumps(result, sort_keys=True)
    for raw_value in ("S-1-fixture", "fixture-class", "fixture-session", "fixture-nas", "fixture-object"):
        assert raw_value not in encoded


def test_launcher_proves_the_lifecycle_selected_before_nps_without_reselection(
    monkeypatch,
) -> None:
    """A second valid lifecycle must not replace the Accounting-first choice."""

    events: list[str] = []
    sources = _Sources(events)
    observed = datetime(2026, 8, 11, 12, 1, tzinfo=UTC)
    sources.accounting = (
        *(
            replace(
                item,
                class_attribute="class-a",
                account_session_id="session-a",
                nas_identity="nas-a",
                principal_observation=(
                    "example.test/Users/fixture-a"
                    if item.packet_type == "access_accept"
                    else ""
                ),
            )
            for item in sources.accounting
        ),
        AccountingObservation(
            packet_type="access_accept",
            observed_at_utc=observed,
            class_attribute="class-b",
            account_session_id="session-b",
            nas_identity="nas-b",
            canonical_record_sha256="d" * 64,
            principal_observation="example.test/Users/fixture-b",
        ),
        AccountingObservation(
            packet_type="start",
            observed_at_utc=observed + timedelta(seconds=5),
            class_attribute="class-b",
            account_session_id="session-b",
            nas_identity="nas-b",
            canonical_record_sha256="e" * 64,
        ),
        AccountingObservation(
            packet_type="stop",
            observed_at_utc=observed + timedelta(minutes=2),
            class_attribute="class-b",
            account_session_id="session-b",
            nas_identity="nas-b",
            canonical_record_sha256="f" * 64,
        ),
    )
    sources.nps = (
        replace(
            sources.nps[0],
            subject_sid="S-1-fixture-a",
            account_session_id="session-a",
            nas_identity="nas-a",
        ),
        NpsObservation(
            event_id=6272,
            observed_at_utc=observed,
            record_id="fixture-nps-b",
            subject_sid="S-1-fixture-b",
            account_session_id="session-b",
            nas_identity="nas-b",
        ),
    )

    def _lookup_ad(principal_observation: str) -> tuple[AdVpnRecord, ...]:
        subject_sid = (
            "S-1-fixture-a"
            if principal_observation.endswith("fixture-a")
            else "S-1-fixture-b"
        )
        events.append(f"ad:{subject_sid}")
        return (
            AdVpnRecord(
                subject_sid=subject_sid,
                immutable_object_id="fixture-object-a",
                enabled=True,
                object_class="user",
                vpn_member=True,
                lookup_principal_observation=principal_observation,
            ),
        )

    monkeypatch.setattr(sources, "lookup_ad", _lookup_ad)
    monkeypatch.setattr(launcher, "verify_collection_identity", _identity)

    result = launcher.launch_probe(
        _Connection(events),
        sources,
        approved_identity=r"EXAMPLE\operator",
        approved_sid="S-1-5-21-100000001-200000001-300000001-1000",
    )

    assert result["terminal_quality_state"] == "proven"
    assert result["counts"]["accounting_records_supplied"] == 6
    assert result["counts"]["nps_events_supplied"] == 2
    assert "ad:S-1-fixture-a" in events
    assert "ad:S-1-fixture-b" not in events


def test_launcher_stops_at_nps_cap_before_ad_lookup(monkeypatch) -> None:
    events: list[str] = []
    sources = _Sources(events, nps_cap=True)
    monkeypatch.setattr(
        launcher, "verify_collection_identity", lambda **kwargs: _identity(**kwargs)
    )

    result = launcher.launch_probe(
        _Connection(events),
        sources,
        approved_identity=r"EXAMPLE\operator",
        approved_sid="S-1-5-21-100000001-200000001-300000001-1000",
    )

    assert result["terminal_quality_state"] == "stopped"
    assert result["cap_and_timeout_flags"]["nps_event_cap_reached"] is True
    assert "ad" not in events


def test_launcher_stops_at_accounting_cap_before_nps_or_ad(monkeypatch) -> None:
    events: list[str] = []
    sources = _Sources(events, accounting_cap=True)
    monkeypatch.setattr(launcher, "verify_collection_identity", _identity)

    result = launcher.launch_probe(
        _Connection(events),
        sources,
        approved_identity=r"EXAMPLE\operator",
        approved_sid="S-1-5-21-100000001-200000001-300000001-1000",
    )

    assert result["terminal_quality_state"] == "stopped"
    assert result["cap_and_timeout_flags"][
        "accounting_candidate_cap_reached"
    ] is True
    assert not any(item.startswith("nps:") for item in events)
    assert "ad" not in events


@pytest.mark.parametrize(
    ("lifecycle_state", "expected_reason", "expected_packet_counts"),
    (
        (
            "missing",
            "no_complete_accounting_lifecycle",
            (1, 1, 0, 0),
        ),
        (
            "ambiguous",
            "accounting_lifecycle_ambiguous",
            (1, 2, 0, 1),
        ),
        (
            "invalid_timestamp",
            "accounting_timestamp_invalid",
            (1, 1, 0, 1),
        ),
    ),
)
def test_launcher_stops_on_invalid_accounting_lifecycle_before_nps_or_ad(
    monkeypatch,
    lifecycle_state: str,
    expected_reason: str,
    expected_packet_counts: tuple[int, int, int, int],
) -> None:
    events: list[str] = []
    sources = _Sources(events)
    if lifecycle_state == "missing":
        sources.accounting = sources.accounting[:-1]
    elif lifecycle_state == "invalid_timestamp":
        sources.accounting = (
            replace(
                sources.accounting[0],
                observed_at_utc=datetime(2026, 8, 11, 12, 0),
            ),
            *sources.accounting[1:],
        )
    else:
        sources.accounting = (*sources.accounting, sources.accounting[1])
    monkeypatch.setattr(launcher, "verify_collection_identity", _identity)

    result = launcher.launch_probe(
        _Connection(events),
        sources,
        approved_identity=r"EXAMPLE\operator",
        approved_sid="S-1-5-21-100000001-200000001-300000001-1000",
    )

    assert result["terminal_quality_state"] == "stopped"
    assert result["stop_reason"] == expected_reason
    assert tuple(
        result["counts"][name]
        for name in (
            "accounting_access_accepts_supplied",
            "accounting_starts_supplied",
            "accounting_interims_supplied",
            "accounting_stops_supplied",
        )
    ) == expected_packet_counts
    assert result["postflight_attestation"] == {
        "performed": True,
        "identity_reverified": True,
        "database_rechecked": True,
        "cursor_unchanged": True,
    }
    assert not any(item.startswith("nps:") for item in events)
    assert "ad" not in events


@pytest.mark.parametrize("match_state", ["missing", "ambiguous"])
def test_launcher_stops_on_invalid_nps_match_with_at_most_one_ad_lookup(
    monkeypatch, match_state: str,
) -> None:
    events: list[str] = []
    sources = _Sources(events)
    if match_state == "missing":
        sources.nps = ()
    else:
        sources.nps = (
            sources.nps[0],
            replace(sources.nps[0], record_id="fixture-nps-duplicate"),
        )
    monkeypatch.setattr(launcher, "verify_collection_identity", _identity)

    result = launcher.launch_probe(
        _Connection(events),
        sources,
        approved_identity=r"EXAMPLE\operator",
        approved_sid="S-1-5-21-100000001-200000001-300000001-1000",
    )

    assert result["terminal_quality_state"] == "stopped"
    assert any(item.startswith("nps:") for item in events)
    assert events.count("ad") == int(match_state == "ambiguous")


def _assert_redacted_nps_boundary_stop(
    result: dict[str, object], *, stop_reason: str, forbidden_value: str,
) -> None:
    assert result["terminal_quality_state"] == "stopped"
    assert result["stop_reason"] == stop_reason
    assert result["provenance_digests"] == {}
    assert result["exact_link_bools"] == {
        "ad_sid_to_vpn_membership": False,
        "nps_subject_sid_to_ad_sid": False,
        "access_accept_class_to_start_stop": False,
    }
    encoded = json.dumps(result, sort_keys=True)
    for raw_value in (
        forbidden_value,
        "fixture-class",
        "fixture-session",
        "fixture-nps",
        "fixture-object",
    ):
        assert raw_value not in encoded


def test_launcher_marks_nps_reader_exception_without_source_detail(monkeypatch) -> None:
    events: list[str] = []
    sources = _Sources(events)
    monkeypatch.setattr(launcher, "verify_collection_identity", _identity)
    monkeypatch.setattr(
        sources,
        "collect_nps",
        lambda _limits: (_ for _ in ()).throw(
            RuntimeError("private_source_detail")
        ),
    )

    result = launcher.launch_probe(
        _Connection(events),
        sources,
        approved_identity=r"EXAMPLE\operator",
        approved_sid="S-1-5-21-100000001-200000001-300000001-1000",
    )

    _assert_redacted_nps_boundary_stop(
        result,
        stop_reason="nps_collect_exception",
        forbidden_value="private_source_detail",
    )
    assert "ad" not in events


def test_launcher_marks_empty_nps_result_without_source_identifiers(
    monkeypatch,
) -> None:
    events: list[str] = []
    sources = _Sources(events)
    sources.nps = ()
    monkeypatch.setattr(launcher, "verify_collection_identity", _identity)

    result = launcher.launch_probe(
        _Connection(events),
        sources,
        approved_identity=r"EXAMPLE\operator",
        approved_sid="S-1-5-21-100000001-200000001-300000001-1000",
    )

    _assert_redacted_nps_boundary_stop(
        result,
        stop_reason="nps_empty_result",
        forbidden_value="private_source_detail",
    )
    assert any(item.startswith("nps:") for item in events)
    assert "ad" not in events


def test_launcher_contains_ad_reader_failure_and_still_runs_postflight(
    monkeypatch,
) -> None:
    events: list[str] = []
    sources = _Sources(events)
    monkeypatch.setattr(launcher, "verify_collection_identity", _identity)
    monkeypatch.setattr(
        sources,
        "lookup_ad",
        lambda _sid: (_ for _ in ()).throw(RuntimeError("private_ad_detail")),
    )

    result = launcher.launch_probe(
        _Connection(events),
        sources,
        approved_identity=r"EXAMPLE\operator",
        approved_sid="S-1-5-21-100000001-200000001-300000001-1000",
    )

    assert result["terminal_quality_state"] == "stopped"
    assert result["postflight_attestation"] == {
        "performed": True,
        "identity_reverified": True,
        "database_rechecked": True,
        "cursor_unchanged": True,
    }
    assert "private_ad_detail" not in json.dumps(result, sort_keys=True)


def test_launcher_records_postflight_database_failure_without_raw_detail(
    monkeypatch,
) -> None:
    events: list[str] = []
    monkeypatch.setattr(launcher, "verify_collection_identity", _identity)

    result = launcher.launch_probe(
        _Connection(
            events,
            result_sets=((_function_row(cursor_revision=3),), ()),
        ),
        _Sources(events),
        approved_identity=r"EXAMPLE\operator",
        approved_sid="S-1-5-21-100000001-200000001-300000001-1000",
    )

    assert result["terminal_quality_state"] == "stopped"
    assert result["postflight_attestation"] == {
        "performed": True,
        "identity_reverified": True,
        "database_rechecked": False,
        "cursor_unchanged": False,
    }
    assert result["provenance_digests"] == {}


def test_launcher_records_postflight_identity_failure_before_database_recheck(
    monkeypatch,
) -> None:
    events: list[str] = []
    identity_calls = 0

    def _verify(**_kwargs: str) -> dict[str, object]:
        nonlocal identity_calls
        identity_calls += 1
        if identity_calls == 1:
            return _identity()
        return {
            "status": "failed",
            "reasons": ["sid_mismatch"],
            "current_principal": r"OTHER\operator",
            "expected_principal": r"EXAMPLE\operator",
            "interactive": True,
            "elevated": False,
        }

    monkeypatch.setattr(launcher, "verify_collection_identity", _verify)

    result = launcher.launch_probe(
        _Connection(events),
        _Sources(events),
        approved_identity=r"EXAMPLE\operator",
        approved_sid="S-1-5-21-100000001-200000001-300000001-1000",
    )

    assert result["terminal_quality_state"] == "stopped"
    assert result["postflight_attestation"] == {
        "performed": True,
        "identity_reverified": False,
        "database_rechecked": False,
        "cursor_unchanged": False,
    }
    assert sum("sli_g11a3_preflight_state_v1" in item for item in events) == 1


def test_launcher_accepts_a_stable_nonzero_cursor_revision(
    monkeypatch,
) -> None:
    events: list[str] = []
    monkeypatch.setattr(launcher, "verify_collection_identity", _identity)

    result = launcher.launch_probe(
        _Connection(events, ((_function_row(cursor_revision=3)),)),
        _Sources(events),
        approved_identity=r"EXAMPLE\operator",
        approved_sid="S-1-5-21-100000001-200000001-300000001-1000",
    )

    assert result["terminal_quality_state"] == "proven"
    assert sum("sli_g11a3_preflight_state_v1" in item for item in events) == 2


def test_launcher_stops_when_cursor_revision_changes_during_probe(
    monkeypatch,
) -> None:
    events: list[str] = []
    monkeypatch.setattr(launcher, "verify_collection_identity", _identity)

    result = launcher.launch_probe(
        _Connection(
            events,
            result_sets=(
                ((_function_row(cursor_revision=3)),),
                ((_function_row(cursor_revision=4)),),
            ),
        ),
        _Sources(events),
        approved_identity=r"EXAMPLE\operator",
        approved_sid="S-1-5-21-100000001-200000001-300000001-1000",
    )

    assert result["terminal_quality_state"] == "stopped"
    assert result["exact_link_bools"] == {
        "ad_sid_to_vpn_membership": False,
        "nps_subject_sid_to_ad_sid": False,
        "access_accept_class_to_start_stop": False,
    }
    assert result["provenance_digests"] == {}
    assert result["postflight_attestation"] == {
        "performed": True,
        "identity_reverified": True,
        "database_rechecked": True,
        "cursor_unchanged": False,
    }
    assert sum("sli_g11a3_preflight_state_v1" in item for item in events) == 2
    assert any(item.startswith("nps:") for item in events)
    assert "accounting:1/400/262144/20" in events
    assert "ad" in events


def test_launcher_contains_accounting_reader_failure_and_rechecks_postflight(
    monkeypatch,
) -> None:
    events: list[str] = []
    sources = _Sources(events)
    monkeypatch.setattr(launcher, "verify_collection_identity", _identity)
    monkeypatch.setattr(
        sources,
        "collect_accounting",
        lambda _limits: (_ for _ in ()).throw(
            RuntimeError("source_reader_failed")
        ),
    )

    result = launcher.launch_probe(
        _Connection(events, ((_function_row(cursor_revision=3)),)),
        sources,
        approved_identity=r"EXAMPLE\operator",
        approved_sid="S-1-5-21-100000001-200000001-300000001-1000",
    )

    assert result["terminal_quality_state"] == "stopped"
    assert result["postflight_attestation"] == {
        "performed": True,
        "identity_reverified": True,
        "database_rechecked": True,
        "cursor_unchanged": True,
    }
    assert not any(item.startswith("nps:") for item in events)
    assert "ad" not in events
    assert sum("sli_g11a3_preflight_state_v1" in item for item in events) == 2


@pytest.mark.parametrize(
    "database_row",
    [(True, False, True, 0), (True, True, False, 0)],
)
def test_launcher_does_not_open_source_when_existing_role_or_worker_is_present(
    monkeypatch, database_row: tuple[bool, bool, bool, int],
) -> None:
    events: list[str] = []
    sources = _Sources(events)
    monkeypatch.setattr(
        launcher, "verify_collection_identity", lambda **kwargs: _identity(**kwargs)
    )

    result = launcher.launch_probe(
        _Connection(events, (database_row,)),
        sources,
        approved_identity=r"EXAMPLE\operator",
        approved_sid="S-1-5-21-100000001-200000001-300000001-1000",
    )

    assert result["terminal_quality_state"] == "stopped"
    assert result["postflight_attestation"] == {
        "performed": False,
        "identity_reverified": False,
        "database_rechecked": False,
        "cursor_unchanged": False,
    }
    assert not any(item.startswith(("nps:", "accounting:", "ad")) for item in events)
