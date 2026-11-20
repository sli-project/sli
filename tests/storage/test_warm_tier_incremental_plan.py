from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

import server.sli.storage.storage_lifecycle_io as stage7_module
import server.sli.storage.warm_tier_incremental_plan_runtime as plan_module

from server.sli.storage.warm_tier_incremental_plan_runtime import (
    IncrementalInputs,
    assess_incremental,
    plan_and_record,
    select_missing_rows,
)
from server.sli.storage.storage_policy import StoragePolicy


@pytest.fixture
def legacy_warm_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    roles = {"4608": "boot_scope", "4624": "open", "4634": "close"}
    monkeypatch.setattr(
        plan_module,
        "resolve_descriptor_retention",
        lambda _source, _stream, event_key, **_kwargs: SimpleNamespace(
            rollup="authentication_session",
            rollup_role=roles[str(event_key)],
            promotion={
                "archive_requirement": "no_archive",
                "read_representation": "derived_only",
                "post_promotion_disposition": "delete_source",
                "executable_lifecycle": "existing_warm_then_retention_executor",
            },
            policy_fingerprint="f" * 64,
        ),
    )


def _inputs(**overrides) -> IncrementalInputs:
    values = {
        "warm_available": True,
        "warm_rows": 100,
        "warm_max_event_id": 100,
        "source_rows": 150,
        "source_max_event_id": 150,
        "appended_rows": 50,
        "eligible_rows": 0,
        "planned_rows": 0,
        "archive_missing": 0,
        "batch_truncated": False,
    }
    values.update(overrides)
    return IncrementalInputs(**values)


def test_waits_cleanly_until_rows_leave_hot_window() -> None:
    plan = assess_incremental(StoragePolicy(), _inputs())

    assert plan["status"] == "waiting_for_data_accumulation"
    assert plan["technical_gate_passed"] is True
    assert plan["manual_action"]["copy_performed"] is False


def test_bounded_archived_batch_becomes_ready_for_manual_copy() -> None:
    plan = assess_incremental(
        StoragePolicy(),
        _inputs(eligible_rows=25, planned_rows=25),
    )

    assert plan["status"] == "ready_for_manual_bounded_copy"
    assert plan["manual_action"]["required"] is True
    assert plan["manual_action"]["authorized_by_this_plan"] is False


def test_candidates_that_are_already_present_do_not_request_a_copy() -> None:
    plan = assess_incremental(
        StoragePolicy(),
        _inputs(eligible_rows=25, planned_rows=0, already_present_rows=25),
    )

    assert plan["status"] == "waiting_for_data_accumulation"
    assert plan["manual_action"]["required"] is False


def test_incomplete_scan_without_a_full_batch_fails_closed() -> None:
    plan = assess_incremental(
        StoragePolicy(),
        _inputs(
            eligible_rows=250_001,
            planned_rows=3,
            candidate_scan_complete=False,
            batch_filled=False,
        ),
    )

    assert plan["status"] == "blocked"
    assert "candidate_scan_limit_exceeded_before_exact_result" in plan["blockers"]


def test_missing_archive_coverage_blocks_copy() -> None:
    plan = assess_incremental(
        StoragePolicy(),
        _inputs(eligible_rows=25, planned_rows=25, archive_missing=1),
    )

    assert plan["status"] == "blocked"
    assert "planned_rows_missing_published_archive_coverage" in plan["blockers"]


def test_public_planner_rejects_caller_supplied_descriptor_evidence(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(plan_module, "build_plan", lambda *args, **kwargs: {
        "status": "ready_for_manual_bounded_copy",
        "planned_batch": {"event_ids": [10, 11, 12]},
    })

    with pytest.raises(TypeError, match="descriptor_context"):
        plan_and_record(
            3,
            3,
            output_path=tmp_path / "plan.json",
            descriptor_context={
                "source": "sli.windows.ad-dc",
                "stream": "Security",
                "event_keys": ["4608", "4624", "4634"],
                "source_event_ids": [10, 11, 12],
                "evidence": [],
                "continuity_declarations": [],
            },
        )


def test_durable_descriptor_selection_freezes_the_real_plan_without_caller_context(
    legacy_warm_auth,
) -> None:
    rows = [
        {"id": 10, "normalized_hash_hex": "a" * 64, "time_created_utc": datetime(2026, 7, 1, tzinfo=timezone.utc)},
        {"id": 11, "normalized_hash_hex": "b" * 64, "time_created_utc": datetime(2026, 7, 1, 0, 1, tzinfo=timezone.utc)},
        {"id": 12, "normalized_hash_hex": "c" * 64, "time_created_utc": datetime(2026, 7, 1, 0, 2, tzinfo=timezone.utc)},
    ]
    result = {"planned_batch": {"limit": 10, "archive_coverage": {"missing": 0, "missing_ids": []}}}

    plan_module.apply_durable_descriptor_selection(
        result,
        rows,
        {
            "event_ids": [10, 11, 12],
            "event_keys": ["4608", "4624", "4634"],
            "declaration_scope_identity": "sli.source-capture-continuity.v1:22:" + "d" * 64,
            "declaration_sha256": "d" * 64,
        },
    )

    assert result["planned_batch"]["event_ids"] == [10, 11, 12]
    assert result["descriptor_lifecycle"]["archive_requirement"] == "no_archive"
    assert result["descriptor_lifecycle"]["continuity_declaration_sha256"] == "d" * 64
    assert "descriptor_context" not in result


def test_missing_durable_declaration_schema_disables_only_derived_selection() -> None:
    transaction_events: list[object] = []

    class Transaction:
        def __enter__(self):
            transaction_events.append("entered")
            return self

        def __exit__(self, exc_type, _exc, _traceback):
            transaction_events.append(("exited", exc_type))
            return False

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute(self, *_args):
            raise RuntimeError("relation source_capture_continuity_declarations does not exist")

    class Conn:
        def cursor(self):
            return Cursor()

        def transaction(self):
            return Transaction()

    assert plan_module._next_durable_descriptor_batch(
        Conn(),
        batch_limit=10,
        hot_cutoff_utc=datetime(2026, 7, 2, tzinfo=timezone.utc),
        warm_cutoff_utc=datetime(2026, 6, 1, tzinfo=timezone.utc),
        port=18123,
    ) is None
    assert transaction_events == ["entered", ("exited", RuntimeError)]


def test_durable_descriptor_selection_pages_and_skips_direct_no_archive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The selector must never materialize the growing declaration history."""
    from server.sli.sources.source_capture_continuity import build_capture_declaration

    declaration = build_capture_declaration({
        "collection_run_id": 1, "raw_log_file_id": 21,
        "raw_log_sha256": "a" * 64, "server_id": 1, "log_source_id": 1,
        "descriptor_source": "sli.windows.ad-dc", "descriptor_stream": "Security",
        "provider_name": "Microsoft-Windows-Security-Auditing",
        "channel_value": "Security", "channel_generation_identity": "stable",
        "selector_event_ids": [4608, 4624, 4634, 4672],
        "query_exhausted": True, "capture_status": "completed",
        "cursor_strategy": "record_id", "capture_after_record_id": 99,
        "capture_latest_record_id": 100, "truncated": False,
        "source_events": [
            {"id": 10, "record_id": 100, "event_key": 4608, "normalized_hash": "b" * 64},
        ],
    }).to_record()
    declaration["id"] = 1
    declaration["current_raw_log_sha256"] = "a" * 64
    source_row = {
        "id": 10, "event_record_id": 100, "event_id": 4608,
        "normalized_hash": "b" * 64, "server_id": 1, "log_source_id": 1,
        "raw_log_file_id": 21, "raw_log_sha256": "a" * 64,
        "channel_value": "Security",
        "provider_name": "Microsoft-Windows-Security-Auditing",
        "time_created_utc": datetime(2026, 7, 1, tzinfo=timezone.utc),
    }

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute(self, query, params=None):
            normalized = " ".join(query.lower().split())
            if (
                "from source_capture_continuity_declarations" in normalized
                and "where d.completeness='complete'" in normalized
            ):
                assert "limit %s" in normalized
                self.current = [declaration]
                self.declaration_query = True
            else:
                self.current = [source_row for event_id in params[0] if event_id == 10]
                self.declaration_query = False

        def fetchall(self):
            if self.declaration_query:
                raise AssertionError("declaration history must be fetched in bounded pages")
            return self.current

        def fetchmany(self, _size):
            result, self.current = self.current, []
            return result

    class Conn:
        def cursor(self):
            return Cursor()

    monkeypatch.setattr(plan_module, "_warm_present_ids", lambda _ids, _port: [])
    monkeypatch.setattr(
        plan_module, "_durable_derived_publication_is_verified", lambda *_args: False,
    )
    selected = plan_module._next_durable_descriptor_batch(
        Conn(), batch_limit=10,
        hot_cutoff_utc=datetime(2026, 7, 2, tzinfo=timezone.utc),
        warm_cutoff_utc=datetime(2026, 6, 1, tzinfo=timezone.utc), port=18123,
    )

    assert selected is None


def test_declaration_source_rows_accepts_exact_zero_match_scope_without_query() -> None:
    class Cursor:
        def execute(self, *_args):
            raise AssertionError("zero-row declaration must not issue an empty ANY query")

    assert plan_module._declaration_source_rows(
        Cursor(), {"covered_source_events": []},
    ) == []


def test_durable_planner_chains_same_scope_across_interleaved_server_declarations(
    monkeypatch, legacy_warm_auth,
) -> None:
    from server.sli.sources.source_capture_continuity import build_capture_declaration

    observed = datetime(2026, 7, 1, tzinfo=timezone.utc)

    def declaration(
        *, run: int, raw: int, server: int, after: int, specs: list[tuple[int, int, int]],
    ) -> dict:
        raw_sha = f"{raw:064x}"
        built = build_capture_declaration({
            "collection_run_id": run, "raw_log_file_id": raw,
            "raw_log_sha256": raw_sha, "server_id": server, "log_source_id": server,
            "descriptor_source": "sli.windows.ad-dc", "descriptor_stream": "Security",
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "channel_value": "Security",
            "channel_generation_identity": "generation-stable",
            "selector_event_ids": [4608, 4624, 4634, 4672],
            "query_exhausted": True,
            "capture_status": "completed",
            "cursor_strategy": "record_id", "capture_after_record_id": after,
            "capture_latest_record_id": specs[-1][1], "truncated": False,
            "source_events": [
                {"id": event_id, "record_id": record_id, "event_key": event_key,
                 "normalized_hash": f"{event_id:064x}"}
                for event_id, record_id, event_key in specs
            ],
        }).to_record()
        return {**built, "id": run, "current_raw_log_sha256": raw_sha}

    a1 = declaration(run=1, raw=21, server=1, after=99, specs=[(10, 100, 4608), (11, 101, 4624)])
    b1 = declaration(run=2, raw=22, server=2, after=199, specs=[(20, 200, 4608)])
    a2 = declaration(run=3, raw=23, server=1, after=101, specs=[(12, 102, 4634)])
    rows = {
        int(item["id"]): {
            "id": int(item["id"]), "event_record_id": int(item["record_id"]),
            "event_id": int(item["event_key"]), "normalized_hash": item["sha256"],
            "server_id": int(entry["server_id"]), "log_source_id": int(entry["log_source_id"]),
            "raw_log_file_id": int(entry["raw_log_file_id"]),
            "raw_log_sha256": entry["raw_log_sha256"], "channel_value": "Security",
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "time_created_utc": observed,
        }
        for entry in (a1, b1, a2)
        for item in entry["covered_source_events"]
    }

    class Cursor:
        current: list[dict]

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute(self, query, params=None):
            if "from source_capture_continuity_declarations" in query:
                self.current = [a1, b1, a2]
            else:
                assert "event_id = any" not in " ".join(query.lower().split())
                self.current = [rows[int(event_id)] for event_id in params[0]]

        def fetchall(self):
            return self.current

        def fetchmany(self, _size):
            return self.current

    class Conn:
        def cursor(self):
            return Cursor()

    monkeypatch.setattr(plan_module, "_warm_present_ids", lambda _ids, _port: [])

    selected = plan_module._next_durable_descriptor_batch(
        Conn(), batch_limit=10,
        hot_cutoff_utc=datetime(2026, 7, 2, tzinfo=timezone.utc),
        warm_cutoff_utc=datetime(2026, 6, 1, tzinfo=timezone.utc), port=18123,
    )

    assert selected is not None
    assert [row["id"] for row in selected[0]] == [10, 11, 12]
    assert len(selected[1]["declaration_members"]) == 2
    result = {"planned_batch": {"limit": 10}}
    plan_module.apply_durable_descriptor_selection(result, *selected)
    assert result["planned_batch"]["rows"] == 3


def test_durable_selector_reaches_eligible_scope_after_ineligible_prefix(
    monkeypatch: pytest.MonkeyPatch, legacy_warm_auth,
) -> None:
    """An immutable non-boot declaration cannot strand a later valid scope."""
    from server.sli.sources.source_capture_continuity import build_capture_declaration

    observed = datetime(2026, 7, 1, tzinfo=timezone.utc)

    def declaration(
        declaration_id: int, *, after: int, server_id: int,
        source_events: list[dict[str, object]],
    ) -> dict[str, object]:
        result = build_capture_declaration({
            "collection_run_id": declaration_id,
            "raw_log_file_id": declaration_id,
            "raw_log_sha256": f"{declaration_id:x}" * 64,
            "server_id": server_id,
            "log_source_id": 1,
            "descriptor_source": "sli.windows.ad-dc",
            "descriptor_stream": "Security",
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "channel_value": "Security",
            "channel_generation_identity": "stable",
            "selector_event_ids": [4608, 4624, 4634, 9999],
            "query_exhausted": True,
            "capture_status": "completed",
            "cursor_strategy": "record_id",
            "capture_after_record_id": after,
            "capture_latest_record_id": int(source_events[-1]["record_id"]),
            "truncated": False,
            "source_events": source_events,
        }).to_record()
        result["id"] = declaration_id
        result["current_raw_log_sha256"] = result["raw_log_sha256"]
        return result

    stale = declaration(1, after=99, server_id=2, source_events=[{
        "id": 10, "record_id": 100, "event_key": 9999,
        "normalized_hash": "a" * 64,
    }])
    eligible = declaration(2, after=199, server_id=1, source_events=[
        {"id": 20, "record_id": 200, "event_key": 4608, "normalized_hash": "b" * 64},
    ])
    declarations = [stale, eligible]
    source_rows = {
        10: {
            "id": 10, "event_record_id": 100, "event_id": 9999,
            "normalized_hash": "a" * 64, "server_id": 2, "log_source_id": 1,
            "raw_log_file_id": 1, "raw_log_sha256": "1" * 64,
            "channel_value": "Security",
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "time_created_utc": observed,
        },
        20: {
            "id": 20, "event_record_id": 200, "event_id": 4608,
            "normalized_hash": "b" * 64, "server_id": 1, "log_source_id": 1,
            "raw_log_file_id": 2, "raw_log_sha256": "2" * 64,
            "channel_value": "Security",
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "time_created_utc": observed,
        },
    }

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute(self, query, params=None):
            if "from source_capture_continuity_declarations" in query:
                after_id = int(params[0])
                self.current = [
                    row for row in declarations if int(row["id"]) > after_id
                ][:int(params[1])]
            else:
                self.current = [source_rows[int(event_id)] for event_id in params[0]]

        def fetchall(self):
            return self.current

        def fetchmany(self, _size):
            return self.current

    class Conn:
        def cursor(self):
            return Cursor()

    monkeypatch.setattr(plan_module, "_warm_present_ids", lambda _ids, _port: [])

    selected = plan_module._next_durable_descriptor_batch(
        Conn(), batch_limit=1,
        hot_cutoff_utc=datetime(2026, 7, 2, tzinfo=timezone.utc),
        warm_cutoff_utc=datetime(2026, 6, 1, tzinfo=timezone.utc), port=18123,
    )

    assert selected is not None
    assert [row["id"] for row in selected[0]] == [20]


def test_durable_selector_fails_closed_when_ineligible_prefix_exceeds_scan_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bounded declaration scan reports exhaustion instead of looping forever."""
    declarations = [
        {"id": 1, "current_raw_log_sha256": "", "raw_log_sha256": ""},
        {"id": 2, "current_raw_log_sha256": "", "raw_log_sha256": ""},
        {"id": 3, "current_raw_log_sha256": "", "raw_log_sha256": ""},
    ]

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute(self, _query, params=None):
            after_id = int(params[0])
            self.current = [
                row for row in declarations if int(row["id"]) > after_id
            ][:int(params[1]) if len(params) > 1 else 1]

        def fetchmany(self, _size):
            return self.current

    class Conn:
        def cursor(self):
            return Cursor()

    monkeypatch.setattr(plan_module, "MAX_DURABLE_DECLARATION_SCAN", 2)

    with pytest.raises(RuntimeError, match="durable_descriptor_declaration_scan_limit_reached"):
        plan_module._next_durable_descriptor_batch(
            Conn(), batch_limit=1,
            hot_cutoff_utc=datetime(2026, 7, 2, tzinfo=timezone.utc),
            warm_cutoff_utc=datetime(2026, 6, 1, tzinfo=timezone.utc), port=18123,
        )


def test_durable_derived_readback_reoffers_only_the_exact_selected_declaration(
    monkeypatch, legacy_warm_auth,
) -> None:
    from server.sli.sources.source_capture_continuity import build_capture_declaration

    observed = datetime(2026, 7, 1, tzinfo=timezone.utc)
    declaration = build_capture_declaration({
        "collection_run_id": 1, "raw_log_file_id": 21,
        "raw_log_sha256": "a" * 64, "server_id": 1, "log_source_id": 1,
        "descriptor_source": "sli.windows.ad-dc", "descriptor_stream": "Security",
        "provider_name": "Microsoft-Windows-Security-Auditing",
        "channel_value": "Security", "channel_generation_identity": "stable",
        "selector_event_ids": [4608, 4624, 4634, 4672],
        "query_exhausted": True, "capture_status": "completed",
        "cursor_strategy": "record_id", "capture_after_record_id": 99,
        "capture_latest_record_id": 102, "truncated": False,
        "source_events": [
            {"id": 10, "record_id": 100, "event_key": 4608, "normalized_hash": "b" * 64},
            {"id": 11, "record_id": 101, "event_key": 4624, "normalized_hash": "c" * 64},
            {"id": 12, "record_id": 102, "event_key": 4634, "normalized_hash": "d" * 64},
        ],
    }).to_record()
    declaration["id"] = 1
    declaration["current_raw_log_sha256"] = "a" * 64
    source_rows = {
        item["id"]: {
            "id": item["id"], "event_record_id": item["record_id"],
            "event_id": item["event_key"], "normalized_hash": item["sha256"],
            "server_id": 1, "log_source_id": 1, "raw_log_file_id": 21,
            "raw_log_sha256": "a" * 64, "channel_value": "Security",
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "time_created_utc": observed,
        }
        for item in declaration["covered_source_events"]
    }

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute(self, query, params=None):
            self.current = (
                [declaration]
                if "from source_capture_continuity_declarations" in query
                else [source_rows[int(event_id)] for event_id in params[0]]
            )

        def fetchall(self):
            return self.current

        def fetchmany(self, _size):
            return self.current

    class Conn:
        def cursor(self):
            return Cursor()

    monkeypatch.setattr(plan_module, "_warm_present_ids", lambda _ids, _port: [])
    monkeypatch.setattr(
        plan_module, "_durable_derived_publication_is_verified",
        lambda *_args: True,
        raising=False,
    )
    selected = plan_module._next_durable_descriptor_batch(
        Conn(), batch_limit=10, hot_cutoff_utc=datetime(2026, 7, 2, tzinfo=timezone.utc),
        warm_cutoff_utc=datetime(2026, 6, 1, tzinfo=timezone.utc), port=18123,
    )
    assert selected is not None
    assert [row["id"] for row in selected[0]] == [10, 11, 12]

    monkeypatch.setattr(
        plan_module, "_durable_derived_publication_is_verified",
        lambda *_args: False,
    )
    selected = plan_module._next_durable_descriptor_batch(
        Conn(), batch_limit=10, hot_cutoff_utc=datetime(2026, 7, 2, tzinfo=timezone.utc),
        warm_cutoff_utc=datetime(2026, 6, 1, tzinfo=timezone.utc), port=18123,
    )
    assert selected is not None
    assert [row["id"] for row in selected[0]] == [10, 11, 12]


def test_source_is_read_only_and_does_not_start_workers() -> None:
    source = (
        Path(plan_module.__file__).read_text(encoding="utf-8").lower()
    )

    assert "insert into" not in source
    assert "delete from" not in source
    assert "update events_v2_core" not in source
    assert "docker start" not in source
    assert "start-process" not in source


def test_real_durable_selection_supports_archive_required_contract(monkeypatch) -> None:
    rows = [
        {"id": 10, "normalized_hash_hex": "a" * 64,
         "time_created_utc": datetime(2026, 7, 1, tzinfo=timezone.utc)},
    ]
    resolution = SimpleNamespace(
        rollup="authentication_session", rollup_role="boot_scope",
        policy_fingerprint="f" * 64,
        promotion={
            "archive_requirement": "archive_required",
            "read_representation": "archived_atomic",
            "post_promotion_disposition": "delete_source_after_verified_promotion",
            "executable_lifecycle": "existing_warm_then_retention_executor",
        },
    )
    monkeypatch.setattr(plan_module, "resolve_descriptor_retention", lambda *_a, **_k: resolution)
    result = {"planned_batch": {"limit": 10}}

    plan_module.apply_durable_descriptor_selection(result, rows, {
        "event_ids": [10], "event_keys": ["4608"],
        "declaration_scope_identity": "scope-a",
        "declaration_sha256": "d" * 64,
        "declaration_ids": [2, 5],
    })

    assert result["descriptor_lifecycle"]["archive_requirement"] == "archive_required"
    assert result["planned_batch"]["archive_coverage"] == {"missing": 0, "missing_ids": []}
    progress = result["descriptor_lifecycle"]["declaration_progress"]
    assert progress["declaration_ids"] == [2, 5]
    assert len(progress["digest"]) == 64


def test_freeze_descriptor_lifecycle_rejects_oversized_declaration_members(
    legacy_warm_auth,
) -> None:
    members = tuple({"id": value} for value in range(plan_module.MAX_DECLARATION_MEMBERS + 1))

    with pytest.raises(ValueError, match="continuity_declaration_member_count_out_of_bounds"):
        plan_module._freeze_descriptor_lifecycle(
            source="sli.windows.ad-dc", stream="Security", event_keys=("4624",),
            continuity_declaration_scope_identity="scope",
            continuity_declaration_sha256="a" * 64,
            continuity_declaration_members=members,
        )


def test_build_declaration_progress_rejects_oversized_declaration_ids() -> None:
    selection = {
        "declaration_ids": list(range(1, plan_module.MAX_DECLARATION_IDS + 2)),
        "declaration_scope_identity": "scope", "declaration_sha256": "a" * 64,
    }

    with pytest.raises(ValueError, match="declaration_progress_id_count_out_of_bounds"):
        plan_module._build_declaration_progress(selection, (1,))


def test_processed_declaration_ledger_skips_interleaved_prefix_beyond_scan_bound(
    monkeypatch: pytest.MonkeyPatch, legacy_warm_auth,
) -> None:
    declarations = [
        {"id": value, "current_raw_log_sha256": "a" * 64,
         "raw_log_sha256": "a" * 64,
         "server_id": 1, "log_source_id": 1,
         "descriptor_source": "sli.windows.ad-dc", "descriptor_stream": "Security",
         "provider_name": "provider", "channel_value": "Security",
         "channel_generation_identity": "generation", "capture_after_record_id": value - 1,
         "capture_latest_record_id": value, "covered_source_events": []}
        for value in range(1, 7)
    ]
    row = {"id": 60, "event_id": 4608, "time_created_utc": datetime(2026, 7, 1, tzinfo=timezone.utc)}

    class Cursor:
        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def execute(self, query, params=None):
            if "source_capture_continuity_declarations" in query:
                after_id, excluded, limit = int(params[0]), set(params[1]), int(params[2])
                self.current = [item for item in declarations
                                if int(item["id"]) > after_id and int(item["id"]) not in excluded][:limit]
            else:
                self.current = [row]
        def fetchmany(self, _size): result, self.current = self.current, []; return result
        def fetchall(self): return self.current

    class Conn:
        def cursor(self): return Cursor()

    monkeypatch.setattr(plan_module, "MAX_DURABLE_DECLARATION_SCAN", 2)
    monkeypatch.setattr(plan_module, "_declaration_source_rows", lambda _cur, declaration: [row] if declaration["id"] == 6 else [])
    monkeypatch.setattr(plan_module, "prepare_descriptor_range", lambda chain, rows, **_kwargs: {
        "event_ids": [60], "event_keys": ["4608"], "supplemental_event_ids": [],
        "declaration_scope_identity": "scope-6", "declaration_sha256": "d" * 64,
        "declaration_members": [],
    })
    monkeypatch.setattr(plan_module, "_warm_present_ids", lambda *_args: set())
    monkeypatch.setattr(plan_module, "_durable_derived_publication_is_verified", lambda *_args: False)

    selected = plan_module._next_durable_descriptor_batch(
        Conn(), batch_limit=1,
        hot_cutoff_utc=datetime(2026, 7, 2, tzinfo=timezone.utc),
        warm_cutoff_utc=datetime(2026, 6, 1, tzinfo=timezone.utc), port=18123,
        processed_declaration_ids={1, 2, 3, 4, 5},
    )

    assert selected is not None
    assert selected[1]["declaration_ids"] == [6]


def test_out_of_order_event_below_max_id_is_selected_when_missing() -> None:
    rows = [
        {"id": 101, "time_created_utc": "later"},
        {"id": 150, "time_created_utc": "earlier"},
        {"id": 102, "time_created_utc": "latest"},
    ]

    selected = select_missing_rows(rows, {101, 150}, limit=10)

    assert [row["id"] for row in selected] == [102]


def test_source_does_not_use_warm_max_id_as_copy_cursor() -> None:
    source = (
        Path(plan_module.__file__).read_text(encoding="utf-8").lower()
    )

    assert "where id > %s\n              and time_created_utc" not in source
    assert "exact_set_difference" in source


def test_full_batch_checkpoints_at_last_selected_time_not_window_end(
    monkeypatch,
) -> None:
    start = datetime(2026, 7, 26, tzinfo=timezone.utc)
    rows = [
        {
            "id": event_id,
            "normalized_hash_hex": f"{event_id:064x}",
            "time_created_utc": start + timedelta(minutes=index),
        }
        for index, event_id in enumerate((101, 102, 103))
    ]
    monkeypatch.setattr(plan_module, "_candidate_page", lambda *a, **k: rows)
    monkeypatch.setattr(plan_module, "_warm_present_ids", lambda ids, port: set())

    planned, scan = plan_module._scan_missing(
        object(),
        warm_max_event_id=100,
        selection_lower_utc=start - timedelta(hours=1),
        hot_cutoff_utc=start + timedelta(hours=1),
        warm_cutoff_utc=start - timedelta(days=300),
        batch_limit=2,
        scan_limit=10,
    )

    assert [row["id"] for row in planned] == [101, 102]
    assert scan["candidate_scan_complete"] is False
    assert scan["checkpoint_upper_utc"] == (
        rows[1]["time_created_utc"] + timedelta(microseconds=1)
    )


def test_selection_lower_includes_appended_ids_with_older_event_time() -> None:
    anchor = datetime(2026, 7, 29, tzinfo=timezone.utc)
    older = datetime(2026, 7, 15, tzinfo=timezone.utc)

    assert plan_module._effective_selection_lower(
        anchor,
        [{"id": 101, "time_created_utc": older}],
    ) == older


def test_warm_present_ids_sends_a_large_batch_as_one_http_call_not_argv(
    monkeypatch,
) -> None:
    # A batch this large would previously have been split into roughly a
    # dozen separate "docker exec clickhouse-client --query ..." subprocess
    # launches to stay under the Windows command-line length limit.
    big_batch = list(range(1, 50_001))
    http_calls: list[tuple[int, str]] = []

    def fake_http_query(port: int, query: str) -> bytes:
        http_calls.append((port, query))
        return b"1\n2\n3\n"

    monkeypatch.setattr(plan_module, "_http_query", fake_http_query)
    # The module no longer imports ``subprocess`` at all (metadata reads
    # and inserts alike now go over the ClickHouse HTTP interface), so the
    # "no subprocess launched for id lookups" invariant this test checks is
    # now structural rather than something to monkeypatch-and-catch.
    assert not hasattr(plan_module, "subprocess")

    present = plan_module._warm_present_ids(big_batch, 8123)

    assert present == {1, 2, 3}
    assert len(http_calls) == 1
    port, query = http_calls[0]
    assert port == 8123
    assert "IN (1,2,3,4,5" in query
    source = Path(plan_module.__file__).read_text(encoding="utf-8")
    assert "12_000" not in source
    assert "chunks" not in source.lower()


def test_warm_state_metadata_reads_never_launch_a_docker_process(monkeypatch) -> None:
    """R15-R18: ``_warm_state`` makes several bounded, read-only ClickHouse
    queries (baseline, table-exists, columns, manifest range). All of them
    must go over the HTTP interface -- none of them may fall back to a
    ``docker exec`` subprocess launch, since a batch-scanning caller can
    call this once per batch."""
    http_calls: list[str] = []
    docker_calls: list[list[str]] = []

    def fake_http_query(port, query, *, timeout=300, params=None):
        http_calls.append(query)
        if "count() AS rows,max(event_id)" in query:
            return b'{"data":[{"rows":"5","max_event_id":"5"}]}'
        if "name='incremental_copy_manifest'" in query:
            return b'{"data":[{"rows":"1"}]}'
        if "countIf(name='selection_mode')" in query:
            return b'{"data":[{"mode_columns":"1","upper_columns":"1"}]}'
        return b'{"data":[{"earliest_legacy":null,"latest_v2_upper":null}]}'

    def fake_docker(args, **_kwargs):
        docker_calls.append(list(args))
        return "0.0.0.0:18123"

    monkeypatch.setattr(plan_module, "_http_query", fake_http_query)
    monkeypatch.setattr(stage7_module, "_docker", fake_docker)

    warm = plan_module._warm_state(18123)

    assert warm["available"] is True
    assert warm["rows"] == 5
    # Four bounded metadata reads (baseline/table/columns/manifest), all
    # via HTTP, zero via a docker subprocess.
    assert len(http_calls) == 4
    assert docker_calls == []


def test_build_plan_reuses_a_caller_supplied_port_without_a_second_docker_lookup(
    monkeypatch,
) -> None:
    docker_calls: list[list[str]] = []

    def fake_docker(args, **_kwargs):
        docker_calls.append(list(args))
        return "0.0.0.0:18123"

    def fake_http_query(port, query, *, timeout=300, params=None):
        raise RuntimeError("clickhouse_unreachable_in_test")

    monkeypatch.setattr(stage7_module, "_docker", fake_docker)
    monkeypatch.setattr(plan_module, "_http_query", fake_http_query)

    result = plan_module.build_plan(port=18123)

    # The warm-tier read failed (as forced above), so the plan reports
    # unavailability rather than raising -- but the key assertion is that
    # no docker process was launched to get here, because the caller
    # already supplied a resolved port.
    assert result["warm"]["available"] is False
    assert docker_calls == []


def test_build_plan_resolves_its_own_port_exactly_once_when_none_supplied(
    monkeypatch,
) -> None:
    docker_calls: list[list[str]] = []

    def fake_docker(args, **_kwargs):
        docker_calls.append(list(args))
        return "0.0.0.0:18123"

    def fake_http_query(port, query, *, timeout=300, params=None):
        raise RuntimeError("clickhouse_unreachable_in_test")

    monkeypatch.setattr(stage7_module, "_docker", fake_docker)
    # Exercise the legacy Windows discovery branch without host configuration.
    monkeypatch.setattr(stage7_module, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(stage7_module, "_warm_endpoint", lambda: None)
    monkeypatch.setattr(plan_module, "_http_query", fake_http_query)

    result = plan_module.build_plan()

    assert result["warm"]["available"] is False
    assert len(docker_calls) == 1
    assert docker_calls[0][:1] == ["port"]
