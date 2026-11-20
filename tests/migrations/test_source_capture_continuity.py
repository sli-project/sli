from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import importlib

import pytest


def _scope(*, status: str = "completed", truncated: bool = False) -> dict[str, object]:
    return {
        "collection_run_id": 11,
        "raw_log_file_id": 22,
        "raw_log_sha256": "a" * 64,
        "server_id": 7,
        "log_source_id": 3,
        "descriptor_source": "sli.windows.ad-dc",
        "descriptor_stream": "Security",
        "provider_name": "Microsoft-Windows-Security-Auditing",
        "channel_value": "Security",
        "channel_generation_identity": "generation-stable",
        "capture_status": status,
        "cursor_strategy": "record_id",
        "capture_after_record_id": 99,
        "capture_latest_record_id": 102,
        "selector_event_ids": [4672, 4634, 4624, 4608, 4624],
        "query_exhausted": True,
        "truncated": truncated,
        "source_events": [
            {"id": 101, "record_id": 100, "event_key": 4608, "normalized_hash": "1" * 64},
            {"id": 102, "record_id": 101, "event_key": 4624, "normalized_hash": "2" * 64},
            {"id": 103, "record_id": 102, "event_key": 4634, "normalized_hash": "3" * 64},
        ],
        "recorded_at_utc": datetime(2026, 8, 23, tzinfo=timezone.utc),
    }


def test_complete_capture_builds_stable_immutable_declaration() -> None:
    """A source change must alter the durable declaration identity, never overwrite it."""
    from server.sli.sources.source_capture_continuity import build_capture_declaration

    first = build_capture_declaration(_scope())
    second = build_capture_declaration(_scope())

    assert first.complete is True
    assert first.scope_identity == second.scope_identity
    assert first.declaration_sha256 == second.declaration_sha256
    assert first.source_event_ids == (101, 102, 103)
    assert first.first_event_record_id == 100
    assert first.last_event_record_id == 102
    assert first.selector_event_ids == (4608, 4624, 4634, 4672)
    assert first.query_exhausted is True


def test_sparse_filtered_capture_binds_covered_bounds_selector_and_exact_rows() -> None:
    from server.sli.sources.source_capture_continuity import build_capture_declaration

    scope = _scope()
    scope.update(
        capture_latest_record_id=150,
        source_events=[
            {"id": 101, "record_id": 100, "event_key": 4608, "normalized_hash": "1" * 64},
            {"id": 102, "record_id": 105, "event_key": 4624, "normalized_hash": "2" * 64},
            {"id": 103, "record_id": 110, "event_key": 4634, "normalized_hash": "3" * 64},
        ],
    )

    declaration = build_capture_declaration(scope)
    record = declaration.to_record()

    assert declaration.first_event_record_id == 100
    assert declaration.last_event_record_id == 150
    assert [row["record_id"] for row in record["covered_source_events"]] == [100, 105, 110]
    assert record["selector_event_ids"] == [4608, 4624, 4634, 4672]
    assert record["query_exhausted"] is True


def test_zero_match_filtered_capture_is_valid_only_with_full_query_proof() -> None:
    from server.sli.sources.source_capture_continuity import CaptureContinuityError, build_capture_declaration

    scope = _scope()
    scope.update(
        capture_after_record_id=150,
        capture_latest_record_id=175,
        source_events=[],
    )

    declaration = build_capture_declaration(scope)
    assert declaration.source_event_ids == ()
    assert declaration.first_event_record_id == 151
    assert declaration.last_event_record_id == 175
    assert declaration.to_record()["covered_source_events"] == []

    for field, value, reason in (
        ("query_exhausted", False, "capture_query_not_exhausted"),
        ("selector_event_ids", [], "capture_selector_event_ids_required"),
    ):
        tampered = dict(scope)
        tampered[field] = value
        with pytest.raises(CaptureContinuityError, match=reason):
            build_capture_declaration(tampered)


def test_selector_bounds_query_and_sparse_source_tampering_changes_or_invalidates_digest() -> None:
    from server.sli.sources.source_capture_continuity import CaptureContinuityError, build_capture_declaration

    scope = _scope()
    baseline = build_capture_declaration(scope)
    changed_selector = dict(scope)
    changed_selector["selector_event_ids"] = [4608, 4624, 4634]
    assert build_capture_declaration(changed_selector).declaration_sha256 != baseline.declaration_sha256

    for changes, reason in (
        ({"query_exhausted": False}, "capture_query_not_exhausted"),
        ({"capture_latest_record_id": 101}, "capture_source_record_out_of_bounds"),
        ({"source_events": [
            {"id": 101, "record_id": 100, "event_key": 9999, "normalized_hash": "1" * 64},
        ]}, "capture_source_event_not_selected"),
    ):
        tampered = dict(scope)
        tampered.update(changes)
        with pytest.raises(CaptureContinuityError, match=reason):
            build_capture_declaration(tampered)


def test_persistence_readback_binds_selector_query_bounds_and_sparse_rows() -> None:
    from server.sli.sources.source_capture_continuity import (
        CaptureContinuityError,
        build_capture_declaration,
        persist_capture_declaration,
    )

    scope = _scope()
    scope.update(
        capture_latest_record_id=150,
        source_events=[
            {"id": 101, "record_id": 100, "event_key": 4608, "normalized_hash": "1" * 64},
            {"id": 102, "record_id": 110, "event_key": 4634, "normalized_hash": "2" * 64},
        ],
    )
    declaration = build_capture_declaration(scope)

    class Cursor:
        def __init__(self, returned: dict) -> None:
            self.returned = returned

        def execute(self, _query, _params) -> None:
            return None

        def fetchone(self):
            return self.returned

    record = declaration.to_record()
    persist_capture_declaration(Cursor(record), declaration)

    for field, value in (
        ("selector_event_ids", [4608, 4624, 4634]),
        ("query_exhausted", False),
        ("capture_latest_record_id", 149),
        ("covered_source_events", record["covered_source_events"][:1]),
    ):
        tampered = dict(record)
        tampered[field] = value
        with pytest.raises(CaptureContinuityError, match="capture_declaration_persistence_mismatch"):
            persist_capture_declaration(Cursor(tampered), declaration)


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"status": "partial_timeout"}, "capture_status_not_complete"),
        ({"truncated": True}, "capture_truncated"),
        ({"status": "failed"}, "capture_status_not_complete"),
    ],
)
def test_non_complete_capture_never_becomes_a_promotion_declaration(
    overrides: dict[str, object], reason: str,
) -> None:
    """Removing the source completeness gate must make this test fail."""
    from server.sli.sources.source_capture_continuity import CaptureContinuityError, build_capture_declaration

    scope = _scope(**overrides)

    with pytest.raises(CaptureContinuityError, match=reason):
        build_capture_declaration(scope)


def test_capture_record_range_must_match_source_native_cursor_boundary() -> None:
    """A declaration may not silently claim a wider or narrower captured range."""
    from server.sli.sources.source_capture_continuity import CaptureContinuityError, build_capture_declaration

    scope = _scope()
    scope["capture_latest_record_id"] = 101

    with pytest.raises(CaptureContinuityError, match="capture_source_record_out_of_bounds"):
        build_capture_declaration(scope)


def test_collection_summary_is_the_only_producer_of_a_complete_capture_scope() -> None:
    """Dropping the source-native completion marker must prevent declaration creation."""
    from server.sli.sources.source_capture_continuity import capture_scope_from_collection_summary

    scope = capture_scope_from_collection_summary(
        {
            "channels": [{
                "file": "Security.jsonl",
                "continuity": {
                    "contract": "sli.source-capture-continuity.v1",
                    "status": "complete",
                    "after_record_id": 99,
                    "latest_record_id": 102,
                    "channel_generation_identity": "generation-stable",
                    "selector_event_ids": [4672, 4634, 4624, 4608, 4624],
                    "query_exhausted": True,
                    "truncated": False,
                },
            }],
        },
        raw_file_name="Security.jsonl",
        base_scope={key: value for key, value in _scope().items() if key not in {
            "capture_status", "cursor_strategy", "capture_after_record_id",
            "capture_latest_record_id", "truncated", "source_events", "recorded_at_utc",
        }},
        source_events=_scope()["source_events"],
    )

    assert scope is not None
    assert scope["capture_status"] == "completed"
    assert scope["cursor_strategy"] == "record_id"
    assert scope["capture_after_record_id"] == 99
    assert scope["capture_latest_record_id"] == 102
    assert scope["selector_event_ids"] == [4608, 4624, 4634, 4672]
    assert scope["query_exhausted"] is True

    no_proof = capture_scope_from_collection_summary(
        {"channels": [{"file": "Security.jsonl", "continuity": {"status": "complete"}}]},
        raw_file_name="Security.jsonl",
        base_scope={},
        source_events=[],
    )
    assert no_proof is None


def test_importer_persists_complete_zero_match_filtered_cycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    importer = importlib.import_module("scripts.import.import_event_jsonl_to_postgres")
    summary = {
        "channels": [{
            "file": "Security.jsonl",
            "channel": "Security",
            "continuity": {
                "contract": "sli.source-capture-continuity.v1",
                "status": "complete",
                "after_record_id": 150,
                "latest_record_id": 175,
                "channel_generation_identity": "generation-stable",
                "selector_event_ids": [4672, 4634, 4624, 4608],
                "query_exhausted": True,
                "truncated": False,
            },
        }],
    }

    class Cursor:
        def execute(self, _query, _params) -> None:
            return None

        def fetchall(self):
            return []

    persisted = []
    monkeypatch.setattr(importer, "_collection_summary", lambda _path: summary)
    monkeypatch.setattr(
        importer, "persist_capture_declaration",
        lambda _cur, declaration: persisted.append(declaration) or declaration,
    )

    assert importer._persist_source_capture_continuity(
        Cursor(),
        path=importer.Path("Security.jsonl"),
        collection_run_id=11,
        raw_log_file_id=22,
        raw_log_sha256="a" * 64,
        server_id=7,
        log_source_id=3,
    ) is True
    assert persisted[0].source_event_ids == ()
    assert persisted[0].selector_event_ids == (4608, 4624, 4634, 4672)


def test_descriptor_selection_uses_only_the_full_durable_scope_and_requires_boot() -> None:
    """Removing scope/hash/boot validation must make this regression fail."""
    from server.sli.sources.source_capture_continuity import (
        CaptureContinuityError,
        build_capture_declaration,
        prepare_descriptor_selection,
    )

    declaration = build_capture_declaration(_scope())
    source_rows = [
        {
            "id": 101,
            "event_record_id": 100,
            "event_id": 4608,
            "normalized_hash": "1" * 64,
            "server_id": 7,
            "log_source_id": 3,
            "raw_log_file_id": 22,
            "raw_log_sha256": "a" * 64,
            "channel_value": "Security",
            "provider_name": "Microsoft-Windows-Security-Auditing",
        },
        {
            "id": 102,
            "event_record_id": 101,
            "event_id": 4624,
            "normalized_hash": "2" * 64,
            "server_id": 7,
            "log_source_id": 3,
            "raw_log_file_id": 22,
            "raw_log_sha256": "a" * 64,
            "channel_value": "Security",
            "provider_name": "Microsoft-Windows-Security-Auditing",
        },
        {
            "id": 103,
            "event_record_id": 102,
            "event_id": 4634,
            "normalized_hash": "3" * 64,
            "server_id": 7,
            "log_source_id": 3,
            "raw_log_file_id": 22,
            "raw_log_sha256": "a" * 64,
            "channel_value": "Security",
            "provider_name": "Microsoft-Windows-Security-Auditing",
        },
    ]

    selection = prepare_descriptor_selection(
        declaration.to_record(), source_rows, batch_limit=10,
    )

    assert selection["event_ids"] == [101, 102, 103]
    assert selection["event_keys"] == ["4608", "4624", "4634"]
    assert selection["declaration_sha256"] == declaration.declaration_sha256

    no_boot_scope = _scope()
    no_boot_scope["capture_after_record_id"] = 100
    no_boot_scope["source_events"] = [
        item for item in no_boot_scope["source_events"] if item["event_key"] != 4608
    ]
    no_boot_declaration = build_capture_declaration(no_boot_scope)
    missing_boot = [row for row in source_rows if row["event_id"] != 4608]
    with pytest.raises(CaptureContinuityError, match="capture_boot_boundary_missing"):
        prepare_descriptor_selection(
            no_boot_declaration.to_record(), missing_boot, batch_limit=10,
        )


def test_descriptor_selection_rejects_stale_or_partial_durable_source_material() -> None:
    """A declaration cannot authorize a subset or changed Storage V2 material."""
    from server.sli.sources.source_capture_continuity import (
        CaptureContinuityError,
        build_capture_declaration,
        prepare_descriptor_selection,
    )

    declaration = build_capture_declaration(_scope())
    rows = [
        {
            "id": item["id"], "event_record_id": item["record_id"],
            "event_id": item["event_key"], "normalized_hash": item["normalized_hash"],
            "server_id": 7, "log_source_id": 3, "raw_log_file_id": 22, "raw_log_sha256": "a" * 64,
            "channel_value": "Security", "provider_name": "Microsoft-Windows-Security-Auditing",
        }
        for item in _scope()["source_events"]
    ]
    rows[1]["normalized_hash"] = "f" * 64

    with pytest.raises(CaptureContinuityError, match="capture_source_material_mismatch"):
        prepare_descriptor_selection(declaration.to_record(), rows, batch_limit=10)

    with pytest.raises(CaptureContinuityError, match="capture_source_material_mismatch"):
        prepare_descriptor_selection(declaration.to_record(), rows[:2], batch_limit=10)


def test_descriptor_range_composes_three_complete_segments_and_separates_4672() -> None:
    from server.sli.sources.source_capture_continuity import (
        CaptureContinuityError,
        build_capture_declaration,
        prepare_descriptor_range,
    )

    event_specs = [
        (101, 100, 4608, "1" * 64, 22, "a" * 64),
        (102, 101, 4624, "2" * 64, 22, "a" * 64),
        (103, 102, 4672, "3" * 64, 23, "b" * 64),
        (104, 103, 4634, "4" * 64, 24, "c" * 64),
    ]
    declarations = []
    for collection_run_id, raw_file_id, after, latest, specs in (
        (11, 22, 99, 101, event_specs[:2]),
        (12, 23, 101, 102, event_specs[2:3]),
        (13, 24, 102, 103, event_specs[3:]),
    ):
        scope = _scope()
        scope.update(
            collection_run_id=collection_run_id,
            raw_log_file_id=raw_file_id,
            raw_log_sha256=specs[0][5],
            capture_after_record_id=after,
            capture_latest_record_id=latest,
            source_events=[
                {
                    "id": event_id,
                    "record_id": record_id,
                    "event_key": event_key,
                    "normalized_hash": digest,
                }
                for event_id, record_id, event_key, digest, _raw_id, _raw_sha in specs
            ],
        )
        declarations.append(build_capture_declaration(scope).to_record())
    rows = [
        {
            "id": event_id,
            "event_record_id": record_id,
            "event_id": event_key,
            "normalized_hash": digest,
            "server_id": 7,
            "log_source_id": 3,
            "raw_log_file_id": raw_file_id,
            "raw_log_sha256": raw_sha,
            "channel_value": "Security",
            "provider_name": "Microsoft-Windows-Security-Auditing",
        }
        for event_id, record_id, event_key, digest, raw_file_id, raw_sha in event_specs
    ]

    selection = prepare_descriptor_range(declarations, rows, batch_limit=10)

    assert selection["event_ids"] == [101, 102, 104]
    assert selection["event_keys"] == ["4608", "4624", "4634"]
    assert selection["supplemental_event_ids"] == [103]
    assert len(selection["declaration_members"]) == 3

    recreated = [dict(item) for item in declarations]
    recreated[1]["channel_generation_identity"] = "generation-recreated"
    with pytest.raises(CaptureContinuityError, match="capture_segment_scope_changed"):
        prepare_descriptor_range(recreated, rows, batch_limit=20)
    assert selection["declaration_scope_identity"].startswith(
        "sli.source-capture-continuity-range.v1:"
    )


def test_descriptor_range_rejects_a_missing_intermediate_segment() -> None:
    from server.sli.sources.source_capture_continuity import (
        CaptureContinuityError,
        build_capture_declaration,
        prepare_descriptor_range,
    )

    first = build_capture_declaration(_scope()).to_record()
    third_scope = _scope()
    third_scope.update(
        collection_run_id=13,
        raw_log_file_id=24,
        raw_log_sha256="c" * 64,
        capture_after_record_id=103,
        capture_latest_record_id=104,
        source_events=[
            {"id": 104, "record_id": 104, "event_key": 4634, "normalized_hash": "4" * 64},
        ],
    )
    third = build_capture_declaration(third_scope).to_record()
    rows = [
        {
            "id": item["id"], "event_record_id": item["record_id"],
            "event_id": item["event_key"], "normalized_hash": item["sha256"],
            "server_id": 7, "log_source_id": 3,
            "raw_log_file_id": declaration["raw_log_file_id"],
            "raw_log_sha256": declaration["raw_log_sha256"],
            "channel_value": "Security",
            "provider_name": "Microsoft-Windows-Security-Auditing",
        }
        for declaration in (first, third)
        for item in declaration["covered_source_events"]
    ]

    with pytest.raises(CaptureContinuityError, match="capture_segment_gap"):
        prepare_descriptor_range([first, third], rows, batch_limit=10)


def test_descriptor_range_composes_sparse_segments_through_empty_middle() -> None:
    from server.sli.sources.source_capture_continuity import (
        CaptureContinuityError,
        build_capture_declaration,
        prepare_descriptor_range,
    )

    def segment(*, run: int, raw: int, after: int, latest: int, events: list[dict]) -> dict:
        scope = _scope()
        scope.update(
            collection_run_id=run,
            raw_log_file_id=raw,
            raw_log_sha256=f"{raw:064x}",
            capture_after_record_id=after,
            capture_latest_record_id=latest,
            source_events=events,
        )
        return build_capture_declaration(scope).to_record()

    first = segment(
        run=1, raw=21, after=99, latest=110,
        events=[
            {"id": 101, "record_id": 100, "event_key": 4608, "normalized_hash": "1" * 64},
            {"id": 102, "record_id": 105, "event_key": 4624, "normalized_hash": "2" * 64},
        ],
    )
    middle = segment(run=2, raw=22, after=110, latest=120, events=[])
    third = segment(
        run=3, raw=23, after=120, latest=130,
        events=[
            {"id": 103, "record_id": 125, "event_key": 4634, "normalized_hash": "3" * 64},
        ],
    )
    rows = [
        {
            "id": item["id"], "event_record_id": item["record_id"],
            "event_id": item["event_key"], "normalized_hash": item["sha256"],
            "server_id": 7, "log_source_id": 3,
            "raw_log_file_id": declaration["raw_log_file_id"],
            "raw_log_sha256": declaration["raw_log_sha256"],
            "channel_value": "Security",
            "provider_name": "Microsoft-Windows-Security-Auditing",
        }
        for declaration in (first, middle, third)
        for item in declaration["covered_source_events"]
    ]

    selection = prepare_descriptor_range([third, middle, first], rows, batch_limit=10)
    assert selection["event_ids"] == [101, 102, 103]
    assert len(selection["declaration_members"]) == 3

    changed_selector = [dict(first), dict(middle), dict(third)]
    changed_selector[1]["selector_event_ids"] = [4608, 4624, 4634]
    with pytest.raises(CaptureContinuityError, match="capture_segment_scope_changed"):
        prepare_descriptor_range(changed_selector, rows, batch_limit=10)


def test_lifecycle_readback_uses_the_persisted_declaration_not_caller_evidence() -> None:
    from server.sli.sources.source_capture_continuity import (
        build_capture_declaration,
        load_verified_lifecycle_context,
    )

    declaration = build_capture_declaration(_scope())
    durable = {**declaration.to_record(), "current_raw_log_sha256": "a" * 64}
    evidence = [
        {
            "id": item["id"], "event_record_id": item["record_id"], "event_id": item["event_key"],
            "server_id": 7, "log_source_id": 3, "channel_id": 9, "raw_log_file_id": 22,
            "logon_id": None if item["event_key"] == 4608 else "0xabc",
            "time_created_utc": datetime(2026, 8, 23, 0, index, tzinfo=timezone.utc),
            "normalized_hash": item["normalized_hash"], "principal": "EXAMPLE\\alice",
            "host": "WS01", "logon_type": "10", "channel_value": "Security",
            "provider_name": "Microsoft-Windows-Security-Auditing", "raw_log_sha256": "a" * 64,
        }
        for index, item in enumerate(_scope()["source_events"])
    ]

    class Cursor:
        def __init__(self) -> None:
            self.calls = 0

        def execute(self, _query, _params) -> None:
            self.calls += 1

        def fetchall(self):
            return [durable] if self.calls == 1 else evidence

    context = load_verified_lifecycle_context(
        Cursor(),
        candidate_rows=[
            {
                "id": item["id"], "normalized_hash": item["normalized_hash"],
                "raw_log_file_id": 22, "server_id": 7, "log_source_id": 3,
                "channel_value": "Security", "provider_name": "Microsoft-Windows-Security-Auditing",
            }
            for item in _scope()["source_events"]
        ],
        lifecycle={
            "source": "sli.windows.ad-dc", "stream": "Security",
            "continuity_declaration_scope_identity": declaration.scope_identity,
            "continuity_declaration_sha256": declaration.declaration_sha256,
        },
    )

    assert [item["source_event_id"] for item in context["evidence"]] == [101, 102, 103]
    assert context["continuity_declarations"][0]["channel_id"] == 9
    assert context["continuity_declarations"][0]["source_hashes"] == ["1" * 64, "2" * 64, "3" * 64]


def test_lifecycle_range_readback_reopens_all_durable_segments_and_supplement() -> None:
    from server.sli.sources.source_capture_continuity import (
        CaptureContinuityError,
        build_capture_declaration,
        load_verified_lifecycle_context,
        prepare_descriptor_range,
    )

    specs = [
        (10, 100, 4608, "1" * 64, 21, "a" * 64),
        (11, 101, 4624, "2" * 64, 21, "a" * 64),
        (13, 102, 4672, "3" * 64, 22, "b" * 64),
        (12, 103, 4634, "4" * 64, 23, "c" * 64),
    ]
    declarations = []
    for run, raw_id, after, capture_specs in (
        (1, 21, 99, specs[:2]), (2, 22, 101, specs[2:3]), (3, 23, 102, specs[3:]),
    ):
        built = build_capture_declaration({
            "collection_run_id": run, "raw_log_file_id": raw_id,
            "raw_log_sha256": capture_specs[0][5], "server_id": 7, "log_source_id": 3,
            "descriptor_source": "sli.windows.ad-dc", "descriptor_stream": "Security",
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "channel_value": "Security",
            "channel_generation_identity": "generation-stable",
            "selector_event_ids": [4608, 4624, 4634, 4672],
            "query_exhausted": True,
            "capture_status": "completed",
            "cursor_strategy": "record_id", "capture_after_record_id": after,
            "capture_latest_record_id": capture_specs[-1][1], "truncated": False,
            "source_events": [
                {"id": event_id, "record_id": record_id, "event_key": event_key,
                 "normalized_hash": digest}
                for event_id, record_id, event_key, digest, _raw, _sha in capture_specs
            ],
        })
        declarations.append({
            **built.to_record(), "current_raw_log_sha256": built.raw_log_sha256,
        })
    evidence = [
        {
            "id": event_id, "event_record_id": record_id, "event_id": event_key,
            "normalized_hash": digest, "server_id": 7, "log_source_id": 3,
            "channel_id": 9, "raw_log_file_id": raw_id, "raw_log_sha256": raw_sha,
            "channel_value": "Security",
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "logon_id": None if event_key == 4608 else "0xabc",
            "time_created_utc": datetime(2026, 8, 23, 0, index, tzinfo=timezone.utc),
            "principal": "EXAMPLE\\alice", "host": "WS01", "logon_type": "10",
        }
        for index, (event_id, record_id, event_key, digest, raw_id, raw_sha)
        in enumerate(specs)
    ]
    selection = prepare_descriptor_range(declarations, evidence, batch_limit=10)
    lifecycle = {
        "source": "sli.windows.ad-dc", "stream": "Security",
        "continuity_declaration_scope_identity": selection["declaration_scope_identity"],
        "continuity_declaration_sha256": selection["declaration_sha256"],
        "continuity_declaration_members": selection["declaration_members"],
        "supplemental_context_ids": selection["supplemental_event_ids"],
    }

    class Cursor:
        current: list[dict]

        def execute(self, query, params) -> None:
            if "from source_capture_continuity_declarations" in query:
                self.current = [
                    row for row in declarations if int(row["raw_log_file_id"]) == int(params[2])
                ]
            else:
                self.current = evidence

        def fetchall(self):
            return self.current

    candidates = [
        {"id": row["id"], "normalized_hash": row["normalized_hash"]}
        for row in evidence if row["event_id"] != 4672
    ]

    context = load_verified_lifecycle_context(
        Cursor(), candidate_rows=candidates, lifecycle=lifecycle,
    )

    assert [row["source_event_id"] for row in context["evidence"]] == [10, 11, 13, 12]
    assert len(context["continuity_declarations"]) == 3
    assert context["evidence"][2]["privilege_marker"] == "4672"

    changed_lifecycle = json.loads(json.dumps(lifecycle))
    changed_lifecycle["continuity_declaration_members"][1]["declaration_sha256"] = "f" * 64
    with pytest.raises(
        CaptureContinuityError, match="capture_range_identity_mismatch",
    ):
        load_verified_lifecycle_context(
            Cursor(), candidate_rows=candidates, lifecycle=changed_lifecycle,
        )

    rebound_lifecycle = json.loads(json.dumps(lifecycle))
    rebound_lifecycle["continuity_declaration_members"][0][
        "first_event_record_id"
    ] += 1
    member_payload = json.dumps(
        rebound_lifecycle["continuity_declaration_members"],
        sort_keys=True,
        separators=(",", ":"),
    )
    rebound_sha = sha256(member_payload.encode("utf-8")).hexdigest()
    rebound_lifecycle["continuity_declaration_sha256"] = rebound_sha
    rebound_lifecycle["continuity_declaration_scope_identity"] = (
        f"sli.source-capture-continuity-range.v1:{rebound_sha}"
    )
    with pytest.raises(
        CaptureContinuityError, match="capture_range_member_mismatch",
    ):
        load_verified_lifecycle_context(
            Cursor(), candidate_rows=candidates, lifecycle=rebound_lifecycle,
        )

    selector_lifecycle = json.loads(json.dumps(lifecycle))
    selector_lifecycle["continuity_declaration_members"][1]["selector_event_ids"] = [
        4608, 4624, 4634,
    ]
    selector_payload = json.dumps(
        selector_lifecycle["continuity_declaration_members"],
        sort_keys=True,
        separators=(",", ":"),
    )
    selector_sha = sha256(selector_payload.encode("utf-8")).hexdigest()
    selector_lifecycle["continuity_declaration_sha256"] = selector_sha
    selector_lifecycle["continuity_declaration_scope_identity"] = (
        f"sli.source-capture-continuity-range.v1:{selector_sha}"
    )
    with pytest.raises(
        CaptureContinuityError, match="capture_range_member_mismatch",
    ):
        load_verified_lifecycle_context(
            Cursor(), candidate_rows=candidates, lifecycle=selector_lifecycle,
        )

    evidence[2]["normalized_hash"] = "f" * 64
    with pytest.raises(
        CaptureContinuityError, match="capture_source_material_mismatch",
    ):
        load_verified_lifecycle_context(
            Cursor(), candidate_rows=candidates, lifecycle=lifecycle,
        )


def test_promotion_recheck_uses_current_db_rows_not_gate_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from server.sli.sources import source_capture_continuity as continuity

    gate = {
        "source": "sli.windows.ad-dc",
        "stream": "Security",
        "continuity_declaration_scope_identity": "scope-1",
        "continuity_declaration_sha256": "a" * 64,
        "source_references": [
            {"id": 101, "sha256": "1" * 64},
            {"id": 102, "sha256": "2" * 64},
        ],
        "event_keys": ["4608", "4624"],
    }
    db_rows = [
        {
            "id": 101, "normalized_hash": "1" * 64, "raw_log_file_id": 22,
            "server_id": 7, "log_source_id": 3, "channel_value": "Security",
            "provider_name": "Microsoft-Windows-Security-Auditing",
        },
        {
            "id": 102, "normalized_hash": "2" * 64, "raw_log_file_id": 22,
            "server_id": 7, "log_source_id": 3, "channel_value": "Security",
            "provider_name": "Microsoft-Windows-Security-Auditing",
        },
    ]

    class Cursor:
        def execute(self, _query, _params) -> None:
            return None

        def fetchall(self):
            return db_rows

    seen: dict[str, object] = {}

    def verified(_cur, *, candidate_rows, lifecycle):
        seen["candidate_rows"] = candidate_rows
        seen["lifecycle"] = lifecycle
        return {"evidence": [{"event_key": 4608}, {"event_key": 4624}]}

    monkeypatch.setattr(continuity, "load_verified_lifecycle_context", verified)
    continuity.recheck_durable_promotion_continuity(
        Cursor(), promotion_gate=gate,
    )

    assert seen["candidate_rows"] == db_rows
    assert seen["lifecycle"] == {
        "source": "sli.windows.ad-dc",
        "stream": "Security",
        "continuity_declaration_scope_identity": "scope-1",
        "continuity_declaration_sha256": "a" * 64,
    }

    db_rows[1]["normalized_hash"] = "f" * 64
    with pytest.raises(continuity.CaptureContinuityError, match="promotion_source_material_changed"):
        continuity.recheck_durable_promotion_continuity(
            Cursor(), promotion_gate=gate,
        )


def test_stage6s_migration_is_independent_of_future_stage12_trust_schema() -> None:
    from pathlib import Path

    migration = Path("config/postgres_migrations/088_source_capture_continuity_declarations.sql").read_text(
        encoding="utf-8",
    )

    assert "version=87 and name='ad_group_membership_warm_facts'" in migration
    assert "ad_infrastructure_trust_warm_facts" not in migration
    assert "migration 088 requires migration 087" in migration
    assert "selector_event_ids jsonb not null" in migration
    assert "query_exhausted boolean not null" in migration
    assert "jsonb_array_length(covered_source_events) > 0" not in migration
    assert "first_event_record_id = capture_after_record_id + 1" in migration
    assert "last_event_record_id = capture_latest_record_id" in migration


def test_stage6s_migration_grants_only_the_required_fk_and_runtime_access() -> None:
    from pathlib import Path

    migration = Path("config/postgres_migrations/088_source_capture_continuity_declarations.sql").read_text(
        encoding="utf-8",
    )

    assert (
        "grant references on table collection_runs, raw_log_files, servers, log_sources\n"
        "    to adlog_storage_owner;"
    ) in migration
    assert (
        "grant select, insert on table source_capture_continuity_declarations\n"
        "    to adlog_user;"
    ) in migration
    assert (
        "grant usage, select on sequence source_capture_continuity_declarations_id_seq\n"
        "    to adlog_user;"
    ) in migration
