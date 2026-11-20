from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import server.sli.storage.storage_lifecycle_io as stage7_module
import server.sli.storage.warm_tier_incremental_copy_runtime as copy_module
import server.sli.storage.warm_tier_incremental_plan_runtime as plan_module
from server.sli.storage.storage_v2_models import canonical_json_bytes, event_core_from_v1
from server.sli.storage.warm_tier_incremental_copy_runtime import (
    _archive_placements,
    _identity,
    _session_plan,
    classify_existing,
    classify_session_existing,
    validate_plan,
)
from server.sli.storage.warm_session_lifecycle import (
    SessionBoundary,
    legacy_base_revision,
)


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


def _row(event_id: int, byte: int = 1) -> dict:
    return {
        "id": event_id,
        "normalized_hash": bytes([byte]) * 32,
        "event_id": 5504,
        "channel_id": 1,
        "time_created_utc": datetime(2026, 7, 26, tzinfo=timezone.utc),
    }


class _CursorConnection:
    def cursor(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None


class _WarmSelectionCursor:
    def __init__(self) -> None:
        self.executed: list[tuple[str, tuple[object, ...]]] = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def execute(self, sql, params=()):
        self.executed.append((" ".join(str(sql).lower().split()), tuple(params)))

    def fetchone(self):
        return {
            "source_rows": 0,
            "source_max_event_id": 0,
            "source_oldest_utc": None,
            "source_newest_utc": None,
            "appended_rows": 0,
            "eligible_rows": 0,
            "archive_only_rows": 0,
            "checked_at_utc": datetime(2026, 8, 3, tzinfo=timezone.utc),
        }

    def fetchall(self):
        return []


class _WarmSelectionConnection:
    def __init__(self) -> None:
        self.cursor_instance = _WarmSelectionCursor()

    def cursor(self):
        return self.cursor_instance


def test_generic_warm_selection_excludes_direct_no_archive_descriptors() -> None:
    connection = _WarmSelectionConnection()
    lower = datetime(2026, 7, 1, tzinfo=timezone.utc)
    hot = datetime(2026, 7, 27, tzinfo=timezone.utc)
    warm = datetime(2025, 8, 3, tzinfo=timezone.utc)

    plan_module._source_summary(
        connection,
        warm_max_event_id=0,
        selection_lower_utc=lower,
        hot_cutoff_utc=hot,
        warm_cutoff_utc=warm,
    )
    plan_module._candidate_page(
        connection,
        warm_max_event_id=0,
        selection_lower_utc=lower,
        hot_cutoff_utc=hot,
        warm_cutoff_utc=warm,
        after=None,
        limit=100,
    )

    assert len(connection.cursor_instance.executed) == 2
    for sql, params in connection.cursor_instance.executed:
        assert "direct_no_archive_exclusion" in sql
        assert "not exists" in sql
        assert "storage_v2_channel" in sql
        assert "storage_v2_provider" in sql
        assert "source_capture_continuity_declarations" in sql
        assert "descriptor_source" in sql
        assert "log_source_id" in sql
        assert ["sli.windows.ad-dc"] * 3 in params
        assert [4608, 4624, 4634] in params
        assert ["Security"] * 3 in params
        assert ["Microsoft-Windows-Security-Auditing"] * 3 in params


class _ArchiveBlockCursor:
    def __init__(self, blocks: list[dict[str, object]]) -> None:
        self.blocks = blocks
        self.executed: list[tuple[str, tuple[object, ...]]] = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def execute(self, sql, params=()):
        self.executed.append((str(sql), tuple(params)))

    def fetchall(self):
        return list(self.blocks)


class _ArchiveBlockConnection:
    def __init__(self, blocks: list[dict[str, object]]) -> None:
        self.cursor_instance = _ArchiveBlockCursor(blocks)

    def cursor(self):
        return self.cursor_instance


def _archive_block(index: int) -> dict[str, object]:
    return {
        "archive_set_id": "set-1",
        "block_index": index,
        "first_event_id": 101,
        "last_event_id": 101,
        "row_count": 1,
        "raw_bytes": 1,
        "compressed_bytes": 1,
        "raw_sha256": b"r" * 32,
        "archive_sha256": b"c" * 32,
        "object_location": f"C:/archive/{index}.jsonl.gz",
    }


def test_archive_blocks_accepts_exactly_128_published_blocks() -> None:
    blocks = [_archive_block(index) for index in range(128)]
    connection = _ArchiveBlockConnection(blocks)

    assert copy_module._archive_blocks(connection, [101]) == blocks
    assert copy_module.MAX_ARCHIVE_BLOCKS == 128
    assert connection.cursor_instance.executed[0][1] == ([101], "event", "published")


def test_archive_blocks_rejects_129_published_blocks() -> None:
    connection = _ArchiveBlockConnection([_archive_block(index) for index in range(129)])

    with pytest.raises(RuntimeError, match="archive_block_count_out_of_bounds"):
        copy_module._archive_blocks(connection, [101])


def _plan(rows: list[dict]) -> dict:
    checked = "2026-08-02T01:24:24+00:00"
    return {
        "package_type": "WARM_TIER_INCREMENTAL_PLAN",
        "contract_version": 2,
        "status": "ready_for_manual_bounded_copy",
        "technical_gate_passed": True,
        "policy": {
            "hot_days": 7,
            "warm_days": 365,
            "archive_auto_delete_enabled": False,
        },
        "measurements": {"warm_max_event_id": 100},
        "source": {"checked_at_utc": checked},
        "generated_at_utc": "2026-08-02T01:24:25+00:00",
        "selection": {
            "mode": "missing_placement_time_window_v2",
            "exact_set_difference": True,
            "lower_utc": "2026-07-25T01:24:24+00:00",
            "eligibility_upper_utc": "2026-07-26T01:24:24+00:00",
            "checkpoint_upper_utc": "2026-07-26T01:24:24+00:00",
            "warm_cutoff_utc": "2025-08-02T01:24:24+00:00",
        },
        "planned_batch": {
            "limit": len(rows),
            "rows": len(rows),
            "event_ids": [row["id"] for row in rows],
            "first_event_id": rows[0]["id"],
            "last_event_id": rows[-1]["id"],
            "identity_sha256": _identity(rows),
            "archive_coverage": {"missing": 0, "missing_ids": []},
        },
    }


def test_plan_freezes_owner_policy_and_exact_identity() -> None:
    frozen = validate_plan(_plan([_row(101), _row(102, 2)]))

    assert frozen["rows"] == 2
    assert frozen["first_event_id"] == 101
    assert frozen["last_event_id"] == 102
    assert frozen["warm_max_event_id"] == 100


def test_plan_rejects_incomplete_archive_coverage() -> None:
    plan = _plan([_row(101)])
    plan["planned_batch"]["archive_coverage"]["missing"] = 1

    with pytest.raises(ValueError, match="archive_coverage"):
        validate_plan(plan)


def test_existing_copy_seam_uses_frozen_no_archive_plan_without_raw_archive(
    monkeypatch, tmp_path: Path, legacy_warm_auth,
) -> None:
    rows = [_row(10, 1), _row(11, 2), _row(12, 3)]
    plan = _plan(rows)
    lifecycle = copy_module._freeze_descriptor_lifecycle(
        source="sli.windows.ad-dc",
        stream="Security",
        event_keys=("4608", "4624", "4634"),
        candidate_ids=(10, 11, 12),
    )
    hashes = [bytes(row["normalized_hash"]).hex() for row in rows]
    plan["descriptor_lifecycle"] = lifecycle
    durable_context = {
        "evidence": [
            {"source_event_id": 10, "source_record_id": 100, "event_key": 4608, "descriptor_source": "sli.windows.ad-dc", "descriptor_stream": "Security", "server_id": 1, "channel_id": 2, "provider_name": "Microsoft-Windows-Security-Auditing", "logon_id": None, "observed_at_utc": "2026-08-02T00:00:00+00:00", "normalized_hash": hashes[0]},
            {"source_event_id": 11, "source_record_id": 101, "event_key": 4624, "descriptor_source": "sli.windows.ad-dc", "descriptor_stream": "Security", "server_id": 1, "channel_id": 2, "provider_name": "Microsoft-Windows-Security-Auditing", "logon_id": "0xabc", "observed_at_utc": "2026-08-02T00:01:00+00:00", "normalized_hash": hashes[1]},
            {"source_event_id": 12, "source_record_id": 102, "event_key": 4634, "descriptor_source": "sli.windows.ad-dc", "descriptor_stream": "Security", "server_id": 1, "channel_id": 2, "provider_name": "Microsoft-Windows-Security-Auditing", "logon_id": "0xabc", "observed_at_utc": "2026-08-02T00:02:00+00:00", "normalized_hash": hashes[2]},
        ],
        "continuity_declarations": [{"scope_identity": "capture-1", "descriptor_source": "sli.windows.ad-dc", "descriptor_stream": "Security", "server_id": 1, "channel_id": 2, "provider_name": "Microsoft-Windows-Security-Auditing", "channel_generation_identity": "generation-stable", "source_event_ids": [10, 11, 12], "source_hashes": hashes, "first_event_record_id": 100, "last_event_record_id": 102, "completeness": "complete"}],
    }
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")

    class Conn:
        def execute(self, _query):
            return None

        def cursor(self):
            return _CursorConnection()

    @contextmanager
    def connect():
        yield Conn()

    monkeypatch.setattr(copy_module, "_connect", connect)
    monkeypatch.setattr(copy_module, "_source_batch", lambda _conn, _frozen: rows)
    monkeypatch.setattr(
        copy_module, "load_verified_lifecycle_context",
        lambda _cur, *, candidate_rows, lifecycle: durable_context,
    )
    monkeypatch.setattr(copy_module, "_archive_blocks", lambda *_args: pytest.fail("raw archive must not be read"))
    monkeypatch.setattr(copy_module, "EVIDENCE_ROOT", tmp_path)

    result = copy_module.execute_and_record(plan_path, execute=False)

    assert result["derived_publication"]["archive"] is None
    assert result["derived_publication"]["manifest"]["readback_required"] is True
    assert result["archive"] == {"required": False, "placement_created": False}
    assert result["readback"]["promotion_eligible"] is False

    persisted: list[tuple[int, dict]] = []

    def persist(port: int, publication: dict) -> dict:
        persisted.append((port, publication))
        return {
            "mode": "published",
            "readback": {
                "status": "verified_persisted_readback",
                "verified": True,
                "promotion_eligible": True,
                "output_identity": "a" * 64,
                "derived_output_digest": publication["derived_output_digest"],
                "published_at_utc": "2026-08-24T10:00:00+00:00",
            },
        }

    monkeypatch.setattr(copy_module, "_persist_derived_publication", persist)
    verified = copy_module.execute_and_record(plan_path, execute=True, port=18123)
    assert verified["status"] == "copied_and_verified"
    assert verified["readback"]["promotion_eligible"] is True
    assert persisted[0][0] == 18123
    assert persisted[0][1]["archive"] is None
    plan["descriptor_lifecycle"]["policy_fingerprint"] = "0" * 64
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    blocked = copy_module.execute_and_record(plan_path, execute=False)
    assert blocked["status"] == "blocked"
    assert blocked["error"] == "frozen_descriptor_lifecycle_mismatch"


def test_no_archive_publication_keeps_frozen_durable_continuity_identity(
    monkeypatch, legacy_warm_auth,
) -> None:
    rows = [_row(10, 1), _row(11, 2), _row(12, 3)]
    hashes = [bytes(row["normalized_hash"]).hex() for row in rows]
    lifecycle = copy_module._freeze_descriptor_lifecycle(
        source="sli.windows.ad-dc",
        stream="Security",
        event_keys=("4608", "4624", "4634"),
        candidate_ids=(10, 11, 12),
        continuity_declaration_scope_identity=(
            "sli.source-capture-continuity.v1:1:" + "a" * 64
        ),
        continuity_declaration_sha256="a" * 64,
    )
    facts = ((10, 100, 4608, None), (11, 101, 4624, "0xabc"), (12, 102, 4634, "0xabc"))
    context = {
        "evidence": [
            {
                "source_event_id": event_id,
                "source_record_id": record_id,
                "event_key": event_key,
                "descriptor_source": "sli.windows.ad-dc",
                "descriptor_stream": "Security",
                "server_id": 1,
                "channel_id": 2,
                "provider_name": "Microsoft-Windows-Security-Auditing",
                "logon_id": logon_id,
                "observed_at_utc": f"2026-08-02T00:0{index}:00+00:00",
                "normalized_hash": hashes[index],
            }
            for index, (event_id, record_id, event_key, logon_id) in enumerate(facts)
        ],
        "continuity_declarations": [{
            "scope_identity": lifecycle["continuity_declaration_scope_identity"],
            "descriptor_source": "sli.windows.ad-dc",
            "descriptor_stream": "Security",
            "server_id": 1,
            "channel_id": 2,
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "channel_generation_identity": "generation-stable",
            "source_event_ids": [10, 11, 12],
            "source_hashes": hashes,
            "first_event_record_id": 100,
            "last_event_record_id": 102,
            "completeness": "complete",
        }],
    }
    monkeypatch.setattr(
        copy_module,
        "load_verified_lifecycle_context",
        lambda _cur, *, candidate_rows, lifecycle: context,
    )

    publication = copy_module._derived_publication_from_frozen_plan(
        _CursorConnection(),
        {"descriptor_lifecycle": lifecycle, "identity_sha256": copy_module._identity(rows)},
        rows,
    )

    assert publication is not None
    assert publication["descriptor_lifecycle"] == lifecycle
    assert publication["descriptor_lifecycle"]["archive_requirement"] == "no_archive"
    assert publication["archive"] is None
    assert publication["source_references"] == [
        {"id": event_id, "sha256": digest}
        for event_id, digest in zip((10, 11, 12), hashes)
    ]
    assert publication["derived"][0]["source_event_ids"] == [10, 11, 12]
    assert publication["derived"][0]["source_hashes"] == hashes

    durable_identity = json.loads(json.dumps(publication))
    rows.clear()
    context["evidence"].clear()
    context["continuity_declarations"].clear()

    assert publication == durable_identity
    assert publication["derived"][0]["source_event_ids"] == [10, 11, 12]
    assert publication["derived"][0]["source_hashes"] == hashes


def test_archive_required_descriptor_uses_the_same_persisted_output_contract(
    monkeypatch, legacy_warm_auth,
) -> None:
    """Archive-required policy still publishes the canonical derived evidence."""
    rows = [_row(10, 1), _row(11, 2), _row(12, 3)]
    hashes = [bytes(row["normalized_hash"]).hex() for row in rows]
    lifecycle = copy_module._freeze_descriptor_lifecycle(
        source="sli.windows.ad-dc",
        stream="Security",
        event_keys=("4608", "4624", "4634"),
        candidate_ids=(10, 11, 12),
        continuity_declaration_scope_identity=(
            "sli.source-capture-continuity.v1:1:" + "a" * 64
        ),
        continuity_declaration_sha256="a" * 64,
    )
    archive_lifecycle = {
        **lifecycle,
        "archive_requirement": "archive_required",
        "read_representation": "archived_atomic",
    }
    context = {
        "evidence": [
            {
                "source_event_id": event_id,
                "source_record_id": record_id,
                "event_key": event_key,
                "descriptor_source": "sli.windows.ad-dc",
                "descriptor_stream": "Security",
                "server_id": 1,
                "channel_id": 2,
                "provider_name": "Microsoft-Windows-Security-Auditing",
                "logon_id": logon_id,
                "observed_at_utc": f"2026-08-02T00:0{index}:00+00:00",
                "normalized_hash": hashes[index],
            }
            for index, (event_id, record_id, event_key, logon_id) in enumerate(
                ((10, 100, 4608, None), (11, 101, 4624, "0xabc"), (12, 102, 4634, "0xabc"))
            )
        ],
        "continuity_declarations": [{
            "scope_identity": archive_lifecycle["continuity_declaration_scope_identity"],
            "descriptor_source": "sli.windows.ad-dc",
            "descriptor_stream": "Security",
            "server_id": 1,
            "channel_id": 2,
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "channel_generation_identity": "generation-stable",
            "source_event_ids": [10, 11, 12],
            "source_hashes": hashes,
            "first_event_record_id": 100,
            "last_event_record_id": 102,
            "completeness": "complete",
        }],
    }
    monkeypatch.setattr(
        copy_module,
        "load_verified_lifecycle_context",
        lambda _cur, *, candidate_rows, lifecycle: context,
    )
    monkeypatch.setattr(
        copy_module, "_freeze_descriptor_lifecycle", lambda **_kwargs: archive_lifecycle,
    )

    publication = copy_module._derived_publication_from_frozen_plan(
        _CursorConnection(),
        {"descriptor_lifecycle": archive_lifecycle, "identity_sha256": _identity(rows)},
        rows,
    )

    assert publication is not None
    assert publication["descriptor_lifecycle"] == archive_lifecycle
    assert publication["manifest"]["archive_requirement"] == "archive_required"
    assert publication["read_availability"] == "source_archived"


def test_4672_enriches_cross_capture_session_without_entering_disposition_manifest(
    monkeypatch, legacy_warm_auth,
) -> None:
    rows = [_row(10, 1), _row(11, 2), _row(12, 4)]
    rows[0]["event_id"] = 4608
    rows[1]["event_id"] = 4624
    rows[2]["event_id"] = 4634
    hashes = {row["id"]: bytes(row["normalized_hash"]).hex() for row in rows}
    hashes[13] = "03" * 32
    members = [
        {"scope_identity": f"capture-{index}", "declaration_sha256": str(index) * 64,
         "raw_log_file_id": 20 + index, "first_event_record_id": record_id,
         "last_event_record_id": record_id}
        for index, record_id in enumerate((100, 101, 102), start=1)
    ]
    member_sha = hashlib.sha256(
        json.dumps(members, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    lifecycle = copy_module._freeze_descriptor_lifecycle(
        source="sli.windows.ad-dc",
        stream="Security",
        event_keys=("4608", "4624", "4634"),
        candidate_ids=(10, 11, 12),
        continuity_declaration_scope_identity=(
            f"sli.source-capture-continuity-range.v1:{member_sha}"
        ),
        continuity_declaration_sha256=member_sha,
        continuity_declaration_members=tuple(members),
        supplemental_context_ids=(13,),
    )
    facts = (
        (10, 100, 4608, None, None),
        (11, 101, 4624, "0xabc", None),
        (13, 102, 4672, "0xabc", "4672"),
        (12, 103, 4634, "0xabc", None),
    )
    context = {
        "evidence": [
            {
                "source_event_id": event_id, "source_record_id": record_id,
                "event_key": event_key, "descriptor_source": "sli.windows.ad-dc",
                "descriptor_stream": "Security", "server_id": 1, "channel_id": 2,
                "provider_name": "Microsoft-Windows-Security-Auditing",
                "logon_id": logon_id,
                "observed_at_utc": f"2026-08-02T00:0{index}:00+00:00",
                "normalized_hash": hashes[event_id], "privilege_marker": privilege,
            }
            for index, (event_id, record_id, event_key, logon_id, privilege)
            in enumerate(facts)
        ],
        "continuity_declarations": [
            {
                "scope_identity": f"capture-{index}",
                "descriptor_source": "sli.windows.ad-dc", "descriptor_stream": "Security",
                "server_id": 1, "channel_id": 2,
                "provider_name": "Microsoft-Windows-Security-Auditing",
                "channel_generation_identity": "generation-stable",
                "source_event_ids": [fact[0]], "source_hashes": [hashes[fact[0]]],
                "first_event_record_id": fact[1], "last_event_record_id": fact[1],
                "completeness": "complete",
            }
            for index, fact in enumerate((facts[0], (11, 101, 4624, None, None), facts[2], facts[3]), start=1)
        ],
    }
    monkeypatch.setattr(
        copy_module, "load_verified_lifecycle_context",
        lambda _cur, *, candidate_rows, lifecycle: context,
    )

    publication = copy_module._derived_publication_from_frozen_plan(
        _CursorConnection(),
        {"descriptor_lifecycle": lifecycle, "identity_sha256": copy_module._identity(rows)},
        rows,
    )

    assert publication is not None
    assert publication["manifest"]["source_ids"] == [10, 11, 12]
    assert publication["derived"][0]["privilege_source_event_id"] == 13
    assert publication["descriptor_lifecycle"]["supplemental_context_ids"] == [13]


def test_derived_output_readback_requires_exact_immutable_identity_and_digest() -> None:
    accepted_derived = [{
        "session_uid": "session-1",
        "state": "closed",
        "coverage_state": "accepted",
        "promotion_eligible": True,
    }]
    publication = {
        "descriptor_lifecycle": {
            "candidate_identity_sha256": "a" * 64,
            "policy_fingerprint": "b" * 64,
            "continuity_declaration_scope_identity": (
                "sli.source-capture-continuity.v1:1:" + "a" * 64
            ),
            "continuity_declaration_sha256": "a" * 64,
        },
        "source_references": [{"id": 10, "sha256": "c" * 64}],
        "derived": accepted_derived,
        "derived_output_digest": copy_module._derived_output_digest(accepted_derived),
        "manifest": {
            "manifest_digest": "d" * 64,
            "source_reference_digest": copy_module._source_reference_digest(
                [{"id": 10, "sha256": "c" * 64}],
            ),
        },
    }
    expected = copy_module._expected_derived_output_row(publication)
    expected["published_at_utc"] = "2026-08-24 10:00:00.000000"

    verified = copy_module.classify_derived_output_readback(publication, [expected])

    assert verified["verified"] is True
    assert verified["promotion_eligible"] is True
    assert verified["output_identity"] == expected["output_identity"]

    unavailable = {
        **publication,
        "derived": [{
            "session_uid": "session-1", "state": "incomplete",
            "coverage_state": "unavailable", "promotion_eligible": False,
        }],
    }
    unavailable["derived_output_digest"] = copy_module._derived_output_digest(
        unavailable["derived"],
    )
    unavailable_row = copy_module._expected_derived_output_row(unavailable)
    unavailable_row["published_at_utc"] = "2026-08-24 10:00:00.000000"
    assert copy_module.classify_derived_output_readback(
        unavailable, [unavailable_row],
    )["promotion_eligible"] is False
    foreign_declaration = dict(expected)
    foreign_declaration["continuity_declaration_scope_identity"] = (
        "sli.source-capture-continuity.v1:2:" + "b" * 64
    )
    foreign_declaration["continuity_declaration_sha256"] = "b" * 64
    with pytest.raises(RuntimeError, match="derived_continuity_scope_identity_mismatch"):
        copy_module.classify_derived_output_readback(
            publication, [foreign_declaration],
        )
    for field, value, error in (
        ("output_identity", "e" * 64, "derived_output_identity_mismatch"),
        ("batch_identity", "f" * 64, "derived_batch_identity_mismatch"),
        ("candidate_identity_sha256", "0" * 64, "derived_candidate_identity_mismatch"),
        ("policy_fingerprint", "1" * 64, "derived_policy_fingerprint_mismatch"),
        ("derived_output_digest", "f" * 64, "derived_output_digest_mismatch"),
        ("source_reference_digest", "0" * 64, "derived_source_reference_mismatch"),
        ("manifest_digest", "1" * 64, "derived_manifest_digest_mismatch"),
        ("source_count", 2, "derived_source_count_mismatch"),
        ("observation_count", 2, "derived_observation_count_mismatch"),
        ("payload_json", "{}", "derived_payload_mismatch"),
    ):
        actual = dict(expected)
        actual[field] = value
        with pytest.raises(RuntimeError, match=error):
            copy_module.classify_derived_output_readback(publication, [actual])
    with pytest.raises(RuntimeError, match="partial_or_duplicate_derived_output"):
        copy_module.classify_derived_output_readback(publication, [])
    with pytest.raises(RuntimeError, match="partial_or_duplicate_derived_output"):
        copy_module.classify_derived_output_readback(publication, [expected, expected])


def test_derived_output_readback_promotion_requires_explicit_true_and_accepted_coverage() -> None:
    publication = {
        "descriptor_lifecycle": {
            "candidate_identity_sha256": "a" * 64,
            "policy_fingerprint": "b" * 64,
            "continuity_declaration_scope_identity": (
                "sli.source-capture-continuity.v1:1:" + "a" * 64
            ),
            "continuity_declaration_sha256": "a" * 64,
        },
        "source_references": [{"id": 10, "sha256": "c" * 64}],
        "manifest": {
            "manifest_digest": "d" * 64,
            "source_reference_digest": copy_module._source_reference_digest(
                [{"id": 10, "sha256": "c" * 64}],
            ),
        },
    }
    promotion_states = (
        ({}, False),
        ({"promotion_eligible": True}, False),
        ({"coverage_state": "accepted"}, False),
        ({"coverage_state": "accepted", "promotion_eligible": None}, False),
        ({"coverage_state": "accepted", "promotion_eligible": "true"}, False),
        ({"coverage_state": "accepted", "promotion_eligible": 1}, False),
        ({"coverage_state": "accepted", "promotion_eligible": False}, False),
        ({"coverage_state": None, "promotion_eligible": True}, False),
        ({"coverage_state": True, "promotion_eligible": True}, False),
        ({"coverage_state": "unavailable", "promotion_eligible": True}, False),
        ({"coverage_state": "accepted", "promotion_eligible": True}, True),
    )

    for promotion_state, eligible in promotion_states:
        derived = [{
            "session_uid": "session-1",
            "state": "closed",
            **promotion_state,
        }]
        candidate = {
            **publication,
            "derived": derived,
            "derived_output_digest": copy_module._derived_output_digest(derived),
        }
        expected = copy_module._expected_derived_output_row(candidate)
        expected["published_at_utc"] = "2026-08-24 10:00:00.000000"

        readback = copy_module.classify_derived_output_readback(candidate, [expected])

        assert readback["promotion_eligible"] is eligible
        assert readback["output_identity"] == expected["output_identity"]


def test_durable_derived_output_presence_requires_complete_exact_readback(
    monkeypatch,
) -> None:
    publication = {
        "descriptor_lifecycle": {
            "candidate_identity_sha256": "a" * 64,
            "policy_fingerprint": "b" * 64,
            "continuity_declaration_scope_identity": (
                "sli.source-capture-continuity.v1:1:" + "a" * 64
            ),
            "continuity_declaration_sha256": "a" * 64,
        },
        "source_references": [{"id": 10, "sha256": "c" * 64}],
        "derived": [{"session_uid": "session-1", "state": "closed"}],
        "derived_output_digest": copy_module._derived_output_digest(
            [{"session_uid": "session-1", "state": "closed"}],
        ),
        "manifest": {
            "manifest_digest": "d" * 64,
            "source_reference_digest": copy_module._source_reference_digest(
                [{"id": 10, "sha256": "c" * 64}],
            ),
        },
    }
    expected = copy_module._expected_derived_output_row(publication)
    expected["published_at_utc"] = "2026-08-24 10:00:00.000000"

    monkeypatch.setattr(copy_module, "_derived_output_actual", lambda *_args: [expected])
    assert copy_module.is_derived_publication_durably_verified(18123, publication) is True

    foreign = dict(expected)
    foreign["manifest_digest"] = "0" * 64
    monkeypatch.setattr(copy_module, "_derived_output_actual", lambda *_args: [foreign])
    assert copy_module.is_derived_publication_durably_verified(18123, publication) is False

    monkeypatch.setattr(copy_module, "_derived_output_actual", lambda *_args: [])
    assert copy_module.is_derived_publication_durably_verified(18123, publication) is False


def test_exact_persisted_derived_output_is_idempotent_without_a_new_write(
    monkeypatch,
) -> None:
    accepted_derived = [{
        "session_uid": "session-1",
        "state": "closed",
        "coverage_state": "accepted",
        "promotion_eligible": True,
    }]
    publication = {
        "descriptor_lifecycle": {
            "candidate_identity_sha256": "a" * 64,
            "policy_fingerprint": "b" * 64,
            "continuity_declaration_scope_identity": (
                "sli.source-capture-continuity.v1:1:" + "a" * 64
            ),
            "continuity_declaration_sha256": "a" * 64,
        },
        "source_references": [{"id": 10, "sha256": "c" * 64}],
        "derived": accepted_derived,
        "derived_output_digest": copy_module._derived_output_digest(accepted_derived),
        "manifest": {
            "manifest_digest": "d" * 64,
            "source_reference_digest": copy_module._source_reference_digest(
                [{"id": 10, "sha256": "c" * 64}],
            ),
        },
    }
    expected = copy_module._expected_derived_output_row(publication)
    expected["published_at_utc"] = "2026-08-24 10:00:00.000000"
    writes: list[str] = []
    monkeypatch.setattr(copy_module, "_apply_session_schema", lambda _port: None)
    monkeypatch.setattr(
        copy_module, "_derived_output_actual", lambda _port, _identity: [expected],
    )
    monkeypatch.setattr(
        copy_module, "_http_query", lambda *_args: writes.append("unexpected_write"),
    )

    result = copy_module._persist_derived_publication(18123, publication)

    assert result["mode"] == "already_published"
    assert result["readback"]["promotion_eligible"] is True
    assert writes == []


def test_plan_accepts_a_short_final_batch_below_the_limit() -> None:
    plan = _plan([_row(101), _row(102, 2)])
    plan["planned_batch"]["limit"] = 10_000

    frozen = validate_plan(plan)

    assert frozen["rows"] == 2


def test_plan_rejects_legacy_max_id_cursor_contract() -> None:
    plan = _plan([_row(101)])
    plan["contract_version"] = 1
    plan["selection"]["mode"] = "legacy_max_event_id_v1"

    with pytest.raises(ValueError, match="gap_safe"):
        validate_plan(plan)


def test_plan_rejects_event_id_list_that_does_not_match_frozen_bounds() -> None:
    plan = _plan([_row(101), _row(103, 2)])
    plan["planned_batch"]["event_ids"] = [101, 102]

    with pytest.raises(ValueError, match="event_ids"):
        validate_plan(plan)


def test_verified_archive_yields_exact_coordinates(monkeypatch, tmp_path: Path) -> None:
    rows = [_row(101), _row(102, 2)]
    lines = [
        json.dumps(
            {
                "kind": "event",
                "row": {
                    "id": row["id"],
                    "normalized_hash": bytes(row["normalized_hash"]).hex(),
                },
            },
            separators=(",", ":"),
        ).encode("utf-8")
        for row in rows
    ]
    raw = b"\n".join(lines) + b"\n"
    compressed = gzip.compress(raw)
    path = tmp_path / "block.jsonl.gz"
    path.write_bytes(compressed)
    block = {
        "object_location": str(path),
        "compressed_bytes": len(compressed),
        "archive_sha256": hashlib.sha256(compressed).digest(),
        "raw_bytes": len(raw),
        "raw_sha256": hashlib.sha256(raw).digest(),
        "row_count": 2,
    }

    placements, evidence = _archive_placements(rows, [block])

    assert [item["id"] for item in placements] == [101, 102]
    assert [item["archive_line"] for item in placements] == [1, 2]
    assert evidence["blocks"] == 1


def _write_archive_block(path: Path, events: list[dict]) -> dict:
    raw = b"".join(
        canonical_json_bytes({"kind": "event", "row": event}) + b"\n"
        for event in events
    )
    compressed = gzip.compress(raw, mtime=0)
    path.write_bytes(compressed)
    return {
        "object_location": str(path.resolve()),
        "compressed_bytes": len(compressed),
        "archive_sha256": hashlib.sha256(compressed).digest(),
        "raw_bytes": len(raw),
        "raw_sha256": hashlib.sha256(raw).digest(),
        "row_count": len(events),
    }


@pytest.fixture
def archive_retry_rows(monkeypatch, tmp_path: Path) -> tuple[dict, dict, dict]:
    original = {
        "id": 101,
        "normalized_hash": "01" * 32,
        "raw_log_file_id": 11,
        "normalized_at": "2026-07-26T01:00:00+00:00",
        "event_id": 5504,
        "server_id": 1,
        "domain_id": 1,
        "log_source_id": 1,
        "channel": "System",
        "time_created_utc": "2026-07-26T00:00:00+00:00",
        "message_text": "synthetic immutable event",
        "record_xml": "<Event />",
        "event_data_json": "{}",
    }
    source = {
        **_row(101),
        "source_core_sha256": event_core_from_v1(
            original, {"channel": {"System": 1}},
        ).source_core_sha256,
    }
    retry = {
        **original,
        "raw_log_file_id": 12,
        "normalized_at": "2026-07-26T02:00:00+00:00",
    }
    return source, original, retry


@pytest.mark.parametrize("reverse_blocks", [False, True])
def test_archive_retry_provenance_uses_the_variant_matching_persisted_core(
    archive_retry_rows, tmp_path: Path, reverse_blocks: bool,
) -> None:
    source, original, retry = archive_retry_rows
    canonical = _write_archive_block(tmp_path / "canonical.gz", [original])
    alternate = _write_archive_block(tmp_path / "retry.gz", [retry])
    blocks = [canonical, alternate]
    if reverse_blocks:
        blocks.reverse()

    placements, evidence = _archive_placements([source], blocks)

    assert placements == [{
        "id": 101,
        "normalized_hash": "01" * 32,
        "archive_file": canonical["object_location"],
        "archive_line": 1,
    }]
    assert evidence["blocks"] == 2
    assert evidence["raw_bytes_verified"] == sum(block["raw_bytes"] for block in blocks)


@pytest.mark.parametrize("reverse_blocks", [False, True])
def test_identical_archive_retries_choose_a_stable_source_matching_placement(
    archive_retry_rows, tmp_path: Path, reverse_blocks: bool,
) -> None:
    source, original, _retry = archive_retry_rows
    first = _write_archive_block(tmp_path / "a.gz", [original])
    second = _write_archive_block(tmp_path / "b.gz", [original])
    blocks = [first, second]
    if reverse_blocks:
        blocks.reverse()

    placements, evidence = _archive_placements([source], blocks)

    assert placements[0]["archive_file"] == first["object_location"]
    assert evidence["blocks"] == 2


@pytest.mark.parametrize("field", ["message_text", "record_xml", "event_data_json", "provider_guid"])
@pytest.mark.parametrize("reverse_blocks", [False, True])
def test_archive_retry_rejects_content_drift_even_with_equal_core_and_normalized_hashes(
    archive_retry_rows, tmp_path: Path, field: str, reverse_blocks: bool,
) -> None:
    source, original, _retry = archive_retry_rows
    changed = {**original, field: "different synthetic content"}
    first = _write_archive_block(tmp_path / "canonical.gz", [original])
    second = _write_archive_block(tmp_path / "conflicting.gz", [changed])
    blocks = [first, second]
    if reverse_blocks:
        blocks.reverse()

    with pytest.raises(RuntimeError, match="archive_event_content_mismatch:101"):
        _archive_placements([source], blocks)


@pytest.mark.parametrize("core_hash,error", [
    (None, "archive_event_source_core_missing"),
    (b"short", "archive_event_source_core_missing"),
    (b"\x00" * 32, "archive_event_source_core_mismatch"),
])
@pytest.mark.parametrize("identical", [False, True])
def test_archive_retry_requires_a_matching_authoritative_core_hash(
    archive_retry_rows, tmp_path: Path, core_hash, error: str, identical: bool,
) -> None:
    source, original, retry = archive_retry_rows
    source["source_core_sha256"] = core_hash
    blocks = [
        _write_archive_block(tmp_path / "first.gz", [original]),
        _write_archive_block(tmp_path / "second.gz", [original if identical else retry]),
    ]

    with pytest.raises(RuntimeError, match=f"{error}:101"):
        _archive_placements([source], blocks)


def test_archive_retry_can_find_the_source_matching_variant_after_two_alternatives(
    archive_retry_rows, tmp_path: Path,
) -> None:
    source, original, retry = archive_retry_rows
    canonical = _write_archive_block(tmp_path / "canonical.gz", [original])
    blocks = [
        _write_archive_block(tmp_path / "first-retry.gz", [retry]),
        _write_archive_block(tmp_path / "second-retry.gz", [{**retry, "raw_log_file_id": 13}]),
        canonical,
    ]

    placements, evidence = _archive_placements([source], blocks)

    assert placements[0]["archive_file"] == canonical["object_location"]
    assert evidence["blocks"] == 3


def test_archive_retry_rejects_distinct_full_variants_matching_the_same_core(
    archive_retry_rows, tmp_path: Path,
) -> None:
    source, original, _retry = archive_retry_rows
    present_null = {**original, "raw_log_file_id": None}
    missing_field = dict(present_null)
    del missing_field["raw_log_file_id"]
    source["source_core_sha256"] = event_core_from_v1(
        present_null, {"channel": {"System": 1}},
    ).source_core_sha256
    blocks = [
        _write_archive_block(tmp_path / "present-null.gz", [present_null]),
        _write_archive_block(tmp_path / "missing-field.gz", [missing_field]),
    ]

    with pytest.raises(RuntimeError, match="archive_event_source_core_ambiguous:101"):
        _archive_placements([source], blocks)


@pytest.mark.parametrize("identical", [False, True])
def test_archive_retry_still_rejects_duplicate_ids_inside_one_block(
    archive_retry_rows, tmp_path: Path, identical: bool,
) -> None:
    source, original, retry = archive_retry_rows
    block = _write_archive_block(
        tmp_path / "duplicate.gz", [original, original if identical else retry],
    )

    with pytest.raises(RuntimeError, match="archive_event_duplicate:101"):
        _archive_placements([source], [block])


@pytest.mark.parametrize("field,value,error", [
    ("raw_sha256", b"\x00" * 32, "archive_raw_mismatch"),
    ("archive_sha256", b"\x00" * 32, "archive_compressed_mismatch"),
    ("row_count", 2, "archive_row_count_mismatch"),
])
def test_archive_retry_fully_verifies_the_unselected_secondary_block(
    archive_retry_rows, tmp_path: Path, field: str, value, error: str,
) -> None:
    source, original, retry = archive_retry_rows
    canonical = _write_archive_block(tmp_path / "canonical.gz", [original])
    alternate = _write_archive_block(tmp_path / "retry.gz", [retry])
    alternate[field] = value

    with pytest.raises(RuntimeError, match=error):
        _archive_placements([source], [canonical, alternate])


def test_archive_retry_retains_all_verified_handles_until_the_lease_closes(
    archive_retry_rows, tmp_path: Path,
) -> None:
    source, original, retry = archive_retry_rows
    blocks = [
        _write_archive_block(tmp_path / "canonical.gz", [original]),
        _write_archive_block(tmp_path / "retry.gz", [retry]),
    ]

    lease, placements, evidence = copy_module._open_verified_archive_placements([source], blocks)
    try:
        assert len(placements) == 1
        assert evidence["blocks"] == len(lease.objects) == 2
        assert all(not item.handle.closed for item in lease.objects)
        lease.verify_identity()
    finally:
        lease.close()
    assert all(item.handle.closed for item in lease.objects)


def test_archive_placements_streams_a_large_archive_within_bounded_memory(
    monkeypatch, tmp_path: Path,
) -> None:
    import tracemalloc

    # The batch under verification is small, but the archive block that must
    # be scanned to find it is much larger -- most lines belong to other,
    # unrelated events, as in a real warm-tier block. A peak-memory bound is
    # only achievable by actually streaming the block instead of buffering
    # the whole compressed/decompressed archive (the previous
    # read_bytes()/gzip.decompress()/splitlines() path).
    matched_rows = [_row(100 + i, byte=(i % 250) + 1) for i in range(500)]
    matched_ids = {row["id"] for row in matched_rows}

    def _line(event_id: int, byte: int) -> bytes:
        return json.dumps(
            {
                "kind": "event",
                "row": {
                    "id": event_id,
                    "normalized_hash": (bytes([byte]) * 32).hex(),
                },
            },
            separators=(",", ":"),
        ).encode("utf-8")

    lines: list[bytes] = []
    matched_iter = iter(matched_rows)
    for index in range(100_000):
        if index % 200 == 0:
            row = next(matched_iter, None)
            if row is not None:
                lines.append(_line(row["id"], row["normalized_hash"][0]))
                continue
        lines.append(_line(10_000_000 + index, (index % 250) + 1))
    raw = b"\n".join(lines) + b"\n"
    compressed = gzip.compress(raw)
    path = tmp_path / "big-block.jsonl.gz"
    path.write_bytes(compressed)
    block = {
        "object_location": str(path),
        "compressed_bytes": len(compressed),
        "archive_sha256": hashlib.sha256(compressed).digest(),
        "raw_bytes": len(raw),
        "raw_sha256": hashlib.sha256(raw).digest(),
        "row_count": len(lines),
    }
    assert len(raw) > 8 * copy_module.ARCHIVE_STREAM_CHUNK_BYTES

    tracemalloc.start()
    placements, evidence = _archive_placements(matched_rows, [block])
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert {item["id"] for item in placements} == matched_ids
    assert evidence["raw_bytes_verified"] == len(raw)
    # Peak Python-tracked memory stays well under the archive's raw size,
    # proving the block is processed in bounded chunks rather than held
    # entirely in memory at once (the old read_bytes()/gzip.decompress()
    # path holds the full compressed buffer, the full decompressed buffer,
    # and a duplicate list of every split line simultaneously -- well over
    # the raw size alone).
    assert peak < len(raw) * 0.6


@pytest.mark.parametrize("relative", [False, True])
def test_archive_placements_rejects_unbounded_db_path(
    tmp_path: Path, relative: bool,
) -> None:
    archive_root = tmp_path / "objects"
    archive_root.mkdir()
    outside = tmp_path / "outside.jsonl.gz"
    raw = b'{"kind":"event","row":{"id":101,"normalized_hash":"' + b"01" * 32 + b'"}}\n'
    compressed = gzip.compress(raw)
    outside.write_bytes(compressed)
    block = {
        "object_location": outside.name if relative else str(archive_root / ".." / outside.name),
        "compressed_bytes": len(compressed),
        "archive_sha256": hashlib.sha256(compressed).digest(),
        "raw_bytes": len(raw),
        "raw_sha256": hashlib.sha256(raw).digest(),
        "row_count": 1,
    }

    with pytest.raises(RuntimeError, match="archive_object_invalid_path"):
        _archive_placements([_row(101)], [block])


def test_archive_placements_rejects_symlink_component(
    monkeypatch, tmp_path: Path,
) -> None:
    archive_root = tmp_path / "objects"
    actual = archive_root / "actual"
    actual.mkdir(parents=True)
    linked = archive_root / "linked"
    try:
        linked.symlink_to(actual, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    path = actual / "block.jsonl.gz"
    raw = b'{"kind":"event","row":{"id":101,"normalized_hash":"' + b"01" * 32 + b'"}}\n'
    compressed = gzip.compress(raw)
    path.write_bytes(compressed)
    block = {
        "object_location": str(linked / path.name),
        "compressed_bytes": len(compressed),
        "archive_sha256": hashlib.sha256(compressed).digest(),
        "raw_bytes": len(raw),
        "raw_sha256": hashlib.sha256(raw).digest(),
        "row_count": 1,
    }

    with pytest.raises(RuntimeError, match="archive_object_reparse_component"):
        _archive_placements([_row(101)], [block])


def test_archive_placements_rejects_jsonl_record_over_explicit_limit(
    monkeypatch, tmp_path: Path,
) -> None:
    monkeypatch.setattr(copy_module, "MAX_ARCHIVE_JSONL_RECORD_BYTES", 128)
    raw = json.dumps({
        "kind": "event",
        "padding": "x" * 512,
        "row": {"id": 101, "normalized_hash": "01" * 32},
    }).encode() + b"\n"
    compressed = gzip.compress(raw)
    path = tmp_path / "huge-line.jsonl.gz"
    path.write_bytes(compressed)
    block = {
        "object_location": str(path.resolve()),
        "compressed_bytes": len(compressed),
        "archive_sha256": hashlib.sha256(compressed).digest(),
        "raw_bytes": len(raw),
        "raw_sha256": hashlib.sha256(raw).digest(),
        "row_count": 1,
    }

    with pytest.raises(RuntimeError, match="archive_jsonl_record_too_large"):
        _archive_placements([_row(101)], [block])


def test_archive_placements_rejects_gzip_bomb_incrementally_at_raw_ceiling(
    monkeypatch, tmp_path: Path,
) -> None:
    monkeypatch.setattr(copy_module, "MAX_ARCHIVE_RAW_BYTES", 256)
    raw = (b'{"kind":"event","row":{"id":999}}\n' * 1000)
    compressed = gzip.compress(raw)
    path = tmp_path / "gzip-bomb.jsonl.gz"
    path.write_bytes(compressed)
    block = {
        "object_location": str(path.resolve()),
        "compressed_bytes": len(compressed),
        "archive_sha256": hashlib.sha256(compressed).digest(),
        # A forged DB ceiling may never defer rejection until full expansion.
        "raw_bytes": 128,
        "raw_sha256": b"x" * 32,
        "row_count": 1000,
    }

    with pytest.raises(RuntimeError, match="archive_raw_bytes_out_of_bounds"):
        _archive_placements([_row(101)], [block])


def test_existing_batch_is_idempotent_or_manifest_recoverable() -> None:
    rows = [_row(101), _row(102, 2)]
    expected = [
        {
            "id": row["id"],
            "normalized_hash": bytes(row["normalized_hash"]).hex(),
            "archive_file": f"C:/archive/{row['id']}.gz",
            "archive_line": 1,
        }
        for row in rows
    ]
    actual = [{**row, "placement": "unclassified"} for row in expected]
    identity = _identity(expected)

    assert classify_existing(expected, [], [], identity) == "new"
    assert (
        classify_existing(expected, actual, [], identity)
        == "recover_manifest"
    )
    assert (
        classify_existing(
            expected,
            actual,
            [{
                "batch_identity": identity,
                "planned_rows": 2,
                "first_event_id": 101,
                "last_event_id": 102,
                "archive_identity_sha256": "a" * 64,
                "selection_mode": copy_module.SELECTION_MODE,
                "selection_lower_utc": "2026-08-01 00:00:00.000000",
                "selection_upper_utc": "2026-08-02 00:00:00.000000",
            }],
            identity,
            frozen={
                "rows": 2, "first_event_id": 101, "last_event_id": 102,
                "identity_sha256": identity,
                "selection_mode": copy_module.SELECTION_MODE,
                "selection_lower_utc": datetime(2026, 8, 1, tzinfo=timezone.utc),
                "checkpoint_upper_utc": datetime(2026, 8, 2, tzinfo=timezone.utc),
            },
            archive={"block_sha256_sequence": "a" * 64},
        )
        == "published"
    )


def test_existing_manifest_with_wrong_selection_cursor_is_not_published() -> None:
    expected = [{
        "id": 101, "normalized_hash": "01" * 32,
        "archive_file": "C:/archive/a.gz", "archive_line": 1,
    }]
    identity = _identity(expected)
    actual = [{**expected[0], "placement": "unclassified"}]

    with pytest.raises(RuntimeError, match="incremental_manifest_contract_mismatch"):
        classify_existing(
            expected, actual, [{
                "batch_identity": identity, "planned_rows": 1,
                "first_event_id": 101, "last_event_id": 101,
                "archive_identity_sha256": "a" * 64,
                "selection_mode": copy_module.SELECTION_MODE,
                "selection_lower_utc": "2026-08-01 00:00:00.000000",
                "selection_upper_utc": "2026-08-02 00:00:01.000000",
            }], identity,
            frozen={
                "rows": 1, "first_event_id": 101, "last_event_id": 101,
                "identity_sha256": identity,
                "selection_mode": copy_module.SELECTION_MODE,
                "selection_lower_utc": datetime(2026, 8, 1, tzinfo=timezone.utc),
                "checkpoint_upper_utc": datetime(2026, 8, 2, tzinfo=timezone.utc),
            },
            archive={"block_sha256_sequence": "a" * 64},
        )


def test_manifest_contract_is_validated_before_session_schema_write(monkeypatch, tmp_path: Path) -> None:
    rows = [_row(101)]
    plan = _plan(rows)
    frozen = validate_plan(plan)
    expected = [{
        "id": 101,
        "normalized_hash": bytes(rows[0]["normalized_hash"]).hex(),
        "archive_file": "C:/archive/a.gz",
        "archive_line": 1,
    }]
    archive = {"block_sha256_sequence": "a" * 64}
    poisoned_manifest = [{
        "batch_identity": frozen["identity_sha256"],
        "planned_rows": 1,
        "first_event_id": 101,
        "last_event_id": 101,
        "archive_identity_sha256": "a" * 64,
        "selection_mode": copy_module.SELECTION_MODE,
        "selection_lower_utc": "2026-07-25 01:24:24.000000",
        "selection_upper_utc": "2026-07-26 01:24:25.000000",
    }]
    writes: list[str] = []

    class Connection:
        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def execute(self, _query): return None

    monkeypatch.setattr(copy_module, "_connect", lambda: Connection())
    monkeypatch.setattr(copy_module, "_source_batch", lambda _conn, _frozen: rows)
    monkeypatch.setattr(copy_module, "_session_boundaries", lambda _rows: [object()])
    monkeypatch.setattr(copy_module, "_archive_blocks", lambda *_args: [])
    monkeypatch.setattr(copy_module, "_archive_placements", lambda *_args: (expected, archive))
    monkeypatch.setattr(copy_module, "_manifest_rows", lambda *_args: poisoned_manifest)
    monkeypatch.setattr(copy_module, "_session_schema_present", lambda _port: False)
    monkeypatch.setattr(copy_module, "_apply_session_schema", lambda _port: writes.append("session_schema"))
    monkeypatch.setattr(copy_module, "_pending_sessions", lambda *_args: [])
    monkeypatch.setattr(copy_module, "_session_plan", lambda *_args: ([], []))
    monkeypatch.setattr(copy_module, "_session_actual", lambda *_args: ([], []))
    monkeypatch.setattr(copy_module, "classify_session_existing", lambda *_args: "new")
    monkeypatch.setattr(copy_module, "_existing_rows", lambda *_args: [{**expected[0], "placement": "unclassified"}])

    with pytest.raises(RuntimeError, match="incremental_manifest_contract_mismatch"):
        copy_module.run(
            tmp_path / "replaced-plan.json", execute=True, port=18123,
            plan_payload=plan,
        )

    assert writes == []


def test_partial_existing_batch_fails_closed() -> None:
    expected = [
        {
            "id": 101,
            "normalized_hash": "01" * 32,
            "archive_file": "C:/archive/a.gz",
            "archive_line": 1,
        },
        {
            "id": 102,
            "normalized_hash": "02" * 32,
            "archive_file": "C:/archive/a.gz",
            "archive_line": 2,
        },
    ]

    with pytest.raises(RuntimeError, match="partial_or_overlapping"):
        classify_existing(
            expected,
            [{**expected[0], "placement": "unclassified"}],
            [{
                "batch_identity": _identity(expected), "planned_rows": 2,
                "first_event_id": 101, "last_event_id": 102,
                "archive_identity_sha256": "a" * 64,
                "selection_mode": copy_module.SELECTION_MODE,
                "selection_lower_utc": "2026-08-01 00:00:00.000000",
                "selection_upper_utc": "2026-08-02 00:00:00.000000",
            }],
            _identity(expected),
            frozen={
                "rows": 2, "first_event_id": 101, "last_event_id": 102,
                "identity_sha256": _identity(expected),
                "selection_mode": copy_module.SELECTION_MODE,
                "selection_lower_utc": datetime(2026, 8, 1, tzinfo=timezone.utc),
                "checkpoint_upper_utc": datetime(2026, 8, 2, tzinfo=timezone.utc),
            },
            archive={"block_sha256_sequence": "a" * 64},
        )


def test_partial_archive_placements_without_manifest_are_recoverable() -> None:
    expected = [
        {"id": 101, "normalized_hash": "01" * 32,
         "archive_file": "C:/archive/a.gz", "archive_line": 1},
        {"id": 102, "normalized_hash": "02" * 32,
         "archive_file": "C:/archive/a.gz", "archive_line": 2},
    ]

    assert classify_existing(
        expected, [{**expected[0], "placement": "unclassified"}], [],
        _identity(expected),
    ) == "recover_placements"


def test_plan_rejects_swapped_declaration_progress(legacy_warm_auth) -> None:
    rows = [_row(101)]
    plan = _plan(rows)
    progress = copy_module._build_declaration_progress({
        "declaration_ids": [7], "declaration_scope_identity": "scope-a",
        "declaration_sha256": "a" * 64,
    }, (101,))
    lifecycle = copy_module._freeze_descriptor_lifecycle(
        source="sli.windows.ad-dc", stream="Security", event_keys=("4608",),
        candidate_ids=(101,), continuity_declaration_scope_identity="scope-a",
        continuity_declaration_sha256="a" * 64, declaration_progress=progress,
    )
    plan["descriptor_lifecycle"] = lifecycle
    plan["descriptor_lifecycle"]["declaration_progress"] = {
        **progress, "declaration_ids": [8],
    }

    with pytest.raises(ValueError, match="declaration_progress_invalid"):
        validate_plan(plan)


def test_archive_required_retry_recovers_torn_publication_after_placements(
    monkeypatch, tmp_path: Path,
) -> None:
    from types import SimpleNamespace

    rows = [_row(101)]
    resolution = SimpleNamespace(
        rollup="authentication_session", rollup_role="boot_scope",
        policy_fingerprint="f" * 64,
        promotion={
            "archive_requirement": "archive_required",
            "read_representation": "archived_atomic",
            "post_promotion_disposition": "delete_source",
            "executable_lifecycle": "existing_warm_then_retention_executor",
        },
    )
    monkeypatch.setattr(plan_module, "resolve_descriptor_retention", lambda *_a, **_k: resolution)
    plan = _plan(rows)
    plan_module.apply_durable_descriptor_selection(plan, [{
        "id": 101, "normalized_hash_hex": "01" * 32,
        "time_created_utc": rows[0]["time_created_utc"],
    }], {
        "event_ids": [101], "event_keys": ["4608"],
        "declaration_scope_identity": "scope-7", "declaration_sha256": "a" * 64,
        "declaration_ids": [7],
    })
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan, default=str), encoding="utf-8")
    frozen = copy_module.validate_plan(plan)
    lifecycle = plan["descriptor_lifecycle"]
    publication = {
        "descriptor_lifecycle": lifecycle,
        "read_availability": "source_archived",
    }
    placements = [{
        "id": 101, "normalized_hash": "01" * 32,
        "archive_file": "C:/archive/a.gz", "archive_line": 1,
    }]
    state = {"placements": [], "manifest": []}

    class Conn:
        def __enter__(self): return self
        def __exit__(self, *_args): return False
        def execute(self, _query): return None
        def cursor(self): return _CursorConnection()

    @contextmanager
    def connect():
        yield Conn()

    monkeypatch.setattr(copy_module, "_connect", connect)
    monkeypatch.setattr(copy_module, "_source_batch", lambda *_args: rows)
    monkeypatch.setattr(copy_module, "_derived_publication_from_frozen_plan", lambda *_args: publication)
    monkeypatch.setattr(copy_module, "_archive_blocks", lambda *_args: [{}])
    monkeypatch.setattr(copy_module, "_archive_placements", lambda *_args: (placements, {
        "required": True, "block_sha256_sequence": "b" * 64,
    }))
    monkeypatch.setattr(copy_module, "_existing_rows", lambda *_args: [
        {**row, "placement": "unclassified"} for row in state["placements"]
    ])
    monkeypatch.setattr(copy_module, "_manifest_rows", lambda *_args: list(state["manifest"]))
    monkeypatch.setattr(copy_module, "_stage_rows", lambda *_args: None)
    monkeypatch.setattr(copy_module, "_drop_database", lambda *_args: None)
    def write_manifest(_port, current_frozen, archive):
        state["manifest"] = [{
            "batch_identity": current_frozen["identity_sha256"],
            "planned_rows": current_frozen["rows"],
            "first_event_id": current_frozen["first_event_id"],
            "last_event_id": current_frozen["last_event_id"],
            "archive_identity_sha256": archive["block_sha256_sequence"],
            "selection_mode": current_frozen["selection_mode"],
            "selection_lower_utc": copy_module._format_utc(current_frozen["selection_lower_utc"]),
            "selection_upper_utc": copy_module._format_utc(current_frozen["checkpoint_upper_utc"]),
        }]
    monkeypatch.setattr(copy_module, "_write_manifest", write_manifest)

    def http_query(_port, query, **_kwargs):
        if "INSERT INTO" in query and "event_placement" in query:
            state["placements"] = list(placements)
        return b""

    monkeypatch.setattr(copy_module, "_http_query", http_query)
    attempts = 0

    def persist(_port, _publication):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("fault_after_archive_publication")
        return {"mode": "published", "readback": {
            "status": "verified_persisted_readback", "verified": True,
            "promotion_eligible": True, "output_identity": "e" * 64,
        }}

    monkeypatch.setattr(copy_module, "_persist_derived_publication", persist)
    monkeypatch.setattr(copy_module, "EVIDENCE_ROOT", tmp_path)

    first = copy_module.execute_and_record(
        plan_path, execute=True, output_path=tmp_path / "first.json", port=18123,
    )
    second = copy_module.execute_and_record(
        plan_path, execute=True, output_path=tmp_path / "second.json", port=18123,
    )

    assert first["status"] == "blocked"
    assert first["error"] == "fault_after_archive_publication"
    assert second["status"] == "already_published"
    assert second["readback"]["promotion_eligible"] is True


def _boundary(event_id: int, role: str, minute: int) -> SessionBoundary:
    return SessionBoundary(
        source_event_id=event_id,
        role=role,
        server_id=1,
        channel_id=2,
        logon_id="0xabc",
        observed_at_utc=datetime(2026, 8, 2, 1, minute, tzinfo=timezone.utc),
        normalized_hash=f"{event_id:064x}"[-64:],
        domain_id=7,
    )


def test_session_plan_is_append_only_for_out_of_order_pair() -> None:
    revisions, placements = _session_plan(
        [], [_boundary(201, "close", 5), _boundary(202, "open", 0)], "a" * 64,
    )

    assert [row["state"] for row in revisions] == ["orphan_logoff", "closed"]
    assert revisions[0]["logon_source_id"] is None
    assert revisions[0]["logoff_source_id"] == 201
    assert revisions[1]["logon_source_id"] == 202
    assert revisions[1]["logoff_source_id"] == 201
    assert {row["event_id"] for row in placements} == {201, 202}


def test_session_plan_closes_legacy_base_without_rewriting_it() -> None:
    legacy = legacy_base_revision(
        session_uid="11" * 16,
        state="open",
        server_id=1,
        domain_id=7,
        channel_id=2,
        logon_id="0xabc",
        logon_source_event_id=100,
        logoff_source_event_id=None,
        logon_time_utc=datetime(2026, 8, 2, 1, 0, tzinfo=timezone.utc),
        logoff_time_utc=None,
    )

    revisions, placements = _session_plan(
        [legacy], [_boundary(101, "close", 5)], "b" * 64,
    )

    assert revisions[0]["session_uid_hex"] == legacy.session_uid
    assert revisions[0]["revision"] == 1
    assert revisions[0]["previous_revision_sha256"] is None
    assert {row["event_id"] for row in placements} == {100, 101}


def test_session_plan_keeps_reused_logon_id_as_independent_open() -> None:
    legacy = legacy_base_revision(
        session_uid="22" * 16,
        state="open",
        server_id=1,
        domain_id=7,
        channel_id=2,
        logon_id="0xabc",
        logon_source_event_id=100,
        logoff_source_event_id=None,
        logon_time_utc=datetime(2026, 8, 2, 1, 0, tzinfo=timezone.utc),
        logoff_time_utc=None,
    )

    revisions, placements = _session_plan(
        [legacy], [_boundary(102, "open", 5)], "d" * 64,
    )

    assert len(revisions) == 1
    assert revisions[0]["state"] == "open"
    assert revisions[0]["session_uid_hex"] != legacy.session_uid
    assert revisions[0]["logon_source_id"] == 102
    assert {row["event_id"] for row in placements} == {102}


def test_session_readback_must_be_exact_before_manifest_recovery() -> None:
    revisions, placements = _session_plan(
        [], [_boundary(301, "open", 0)], "c" * 64,
    )
    assert classify_session_existing(revisions, placements, [], []) == "new"
    assert (
        classify_session_existing(revisions, placements, revisions, placements)
        == "present"
    )
    with pytest.raises(RuntimeError, match="partial_or_mismatched"):
        classify_session_existing(revisions, placements, revisions, [])


def test_drain_backlog_copies_batches_in_process_until_data_runs_out(
    monkeypatch, tmp_path: Path,
) -> None:
    plans = iter([
        {
            "status": "ready_for_manual_bounded_copy",
            "planned_batch": {"rows": 4_000},
            "selection": {"eligibility_upper_utc": "2026-07-27T00:00:00+00:00"},
        },
        {
            "status": "ready_for_manual_bounded_copy",
            "planned_batch": {"rows": 4_000},
            "selection": {"eligibility_upper_utc": "2026-07-27T00:00:00+00:00"},
        },
        {
            "status": "waiting_for_data_accumulation",
            "planned_batch": {"rows": 0},
            "selection": {"eligibility_upper_utc": "2026-07-27T00:00:00+00:00"},
        },
    ])
    plan_calls: list[tuple] = []
    copy_calls: list[Path] = []

    ports_seen: list[int] = []

    def fake_plan_and_record(batch_limit, scan_limit, *, output_path, port=None):
        plan_calls.append((batch_limit, scan_limit, output_path))
        ports_seen.append(port)
        return next(plans)

    def fake_execute_and_record(plan_path, *, execute, port=None):
        copy_calls.append(plan_path)
        ports_seen.append(port)
        batch_identity = ("a" if len(copy_calls) == 1 else "b") * 64
        return {
            "status": "copied_and_verified",
            "plan": {"batch_identity": batch_identity},
        }

    monkeypatch.setattr(
        "server.sli.storage.warm_tier_incremental_plan_runtime.plan_and_record",
        fake_plan_and_record,
    )
    monkeypatch.setattr(copy_module, "execute_and_record", fake_execute_and_record)
    monkeypatch.setattr(copy_module, "_container_port", lambda container: 18123)

    result = copy_module.drain_warm_tier_backlog(
        batch_limit=4_000,
        scan_limit=100_000,
        max_batches=200,
        plan_output_path=tmp_path / "plan.json",
    )

    assert result["status"] == "drained"
    assert result["batches"] == 2
    assert result["copied_rows"] == 8_000
    assert result["completed_copy_paths"] == [
        str(copy_module.EVIDENCE_ROOT / ("warm-tier-incremental-copy-" + "a" * 16 + ".json")),
        str(copy_module.EVIDENCE_ROOT / ("warm-tier-incremental-copy-" + "b" * 16 + ".json")),
    ]
    assert result["completed_packages"] == []
    # No subprocess.* call anywhere in this path -- planning and copying
    # both batches happened as plain in-process function calls, inside the
    # single process this function itself runs in.
    assert len(plan_calls) == 3
    assert len(copy_calls) == 2
    # The container port is resolved exactly once for the whole drain
    # cycle (one ``docker port`` OS process launch, not one per batch) and
    # the same value is threaded through every plan/copy call.
    assert ports_seen == [18123] * 5


def test_drain_backlog_returns_archive_required_promotion_evidence(
    monkeypatch, tmp_path: Path,
) -> None:
    """Archive-required output must remain an exact package for retention."""
    plans = iter([
        {
                "status": "ready_for_manual_bounded_copy",
                "planned_batch": {"rows": 2},
                "selection": {
                    "eligibility_upper_utc": "2026-07-27T00:00:00+00:00",
                    "durable_declaration_frontier_id": 8,
                },
        },
        {
            "status": "waiting_for_data_accumulation",
            "planned_batch": {"rows": 0},
        },
    ])

    monkeypatch.setattr(
        "server.sli.storage.warm_tier_incremental_plan_runtime.plan_and_record",
        lambda *_args, **_kwargs: next(plans),
    )
    progress = copy_module._build_declaration_progress({
        "declaration_ids": [8], "declaration_scope_identity": "scope-8",
        "declaration_sha256": "d" * 64,
    }, (10, 11))
    monkeypatch.setattr(
        copy_module,
        "execute_and_record",
        lambda *_args, **_kwargs: {
            "status": "copied_and_verified",
            "plan": {"batch_identity": "a" * 64},
            "descriptor_lifecycle": {
                "archive_requirement": "archive_required",
                "declaration_progress": progress,
            },
            "derived_publication": {"source_references": []},
            "readback": {
                "promotion_eligible": True, "output_identity": "e" * 64,
            },
        },
    )
    monkeypatch.setattr(copy_module, "_container_port", lambda _container: 18123)

    result = copy_module.drain_warm_tier_backlog(
        batch_limit=2,
        scan_limit=10_000,
        max_batches=1,
        plan_output_path=tmp_path / "plan.json",
    )

    assert result["status"] == "drained"
    assert result["completed_packages"] == [{
        "promotion_evidence_path": str(
            copy_module.EVIDENCE_ROOT / ("warm-tier-incremental-copy-" + "a" * 16 + ".json")
        ),
        "declaration_frontier_id": 8,
        "declaration_progress": progress,
        "promotion_output_identity": "e" * 64,
    }]


def test_drain_backlog_stops_at_a_bad_batch_without_losing_prior_batches(
    monkeypatch, tmp_path: Path,
) -> None:
    """R57: a single bad item's batch is the only one marked failed; a batch
    already copied earlier in the drain loop is not retried or discarded,
    and the overall drain status is never a false success."""

    def fake_plan_and_record(batch_limit, scan_limit, *, output_path, port=None):
        return {
            "status": "ready_for_manual_bounded_copy",
            "planned_batch": {"rows": 10_000},
            "selection": {"eligibility_upper_utc": "2026-07-27T00:00:00+00:00"},
        }

    copy_attempts: list[int] = []

    def fake_execute_and_record(plan_path, *, execute, port=None):
        copy_attempts.append(len(copy_attempts) + 1)
        if len(copy_attempts) == 2:
            return {
                "status": "blocked",
                "error": "archive_event_hash_mismatch:99",
            }
        return {"status": "copied_and_verified", "plan": {"batch_identity": "a" * 64}}

    monkeypatch.setattr(
        "server.sli.storage.warm_tier_incremental_plan_runtime.plan_and_record",
        fake_plan_and_record,
    )
    monkeypatch.setattr(copy_module, "execute_and_record", fake_execute_and_record)
    monkeypatch.setattr(copy_module, "_container_port", lambda container: 18123)

    result = copy_module.drain_warm_tier_backlog(
        batch_limit=10_000,
        scan_limit=100_000,
        max_batches=200,
        plan_output_path=tmp_path / "plan.json",
    )

    assert result["status"] == "blocked"
    assert result["error"] == "archive_event_hash_mismatch:99"
    # Batch 1 was already committed (copied_rows reflects it) before batch
    # 2's single bad item stopped the loop; batch 1 is not retried.
    assert result["batches"] == 1
    assert result["copied_rows"] == 10_000
    assert copy_attempts == [1, 2]


@pytest.mark.parametrize("batch_count", [1, 5])
def test_drain_backlog_launches_exactly_one_docker_process_regardless_of_batch_count(
    monkeypatch, tmp_path: Path, batch_count: int,
) -> None:
    """R15-R18: the number of real OS-process launches this function makes
    must not grow with how many warm-tier batches it drains in one cycle.

    ``_docker`` (``subprocess.run(["docker", ...])``) is the actual
    external-process boundary underneath ``_container_port`` -- the only
    remaining subprocess launch anywhere in the drain path, since metadata
    reads and inserts both now go over the ClickHouse HTTP interface. This
    counts calls at that real boundary, not just the top-level ``invoke()``
    a subprocess-per-batch regression could hide behind."""
    docker_calls: list[list[str]] = []

    def fake_docker(args, **_kwargs):
        docker_calls.append(list(args))
        assert args[:1] == ["port"], "only the port lookup should reach _docker"
        return "0.0.0.0:18123"

    monkeypatch.setattr(stage7_module, "_docker", fake_docker)
    # Exercise the legacy Windows discovery branch without host configuration.
    monkeypatch.setattr(stage7_module, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(stage7_module, "_warm_endpoint", lambda: None)

    plans = iter(
        [
            {
                "status": "ready_for_manual_bounded_copy",
                "planned_batch": {"rows": 1_000},
                "selection": {"eligibility_upper_utc": "2026-07-27T00:00:00+00:00"},
            }
            for _ in range(batch_count)
        ]
        + [
            {
                "status": "waiting_for_data_accumulation",
                "planned_batch": {"rows": 0},
                "selection": {"eligibility_upper_utc": "2026-07-27T00:00:00+00:00"},
            }
        ]
    )

    def fake_plan_and_record(batch_limit, scan_limit, *, output_path, port=None):
        return next(plans)

    def fake_execute_and_record(plan_path, *, execute, port=None):
        return {"status": "copied_and_verified", "plan": {"batch_identity": "a" * 64}}

    monkeypatch.setattr(
        "server.sli.storage.warm_tier_incremental_plan_runtime.plan_and_record",
        fake_plan_and_record,
    )
    monkeypatch.setattr(copy_module, "execute_and_record", fake_execute_and_record)

    result = copy_module.drain_warm_tier_backlog(
        batch_limit=1_000,
        scan_limit=100_000,
        max_batches=200,
        plan_output_path=tmp_path / "plan.json",
    )

    assert result["status"] == "drained"
    assert result["batches"] == batch_count
    # Exactly one ``docker`` process launch for the whole cycle, whether it
    # drains 1 batch or 5 -- not one (or two) per batch.
    assert len(docker_calls) == 1


def test_clickhouse_json_reader_adds_explicit_json_each_row(monkeypatch) -> None:
    seen: list[str] = []

    def fake_query(port: int, query: str) -> bytes:
        seen.append(query)
        return b'{"value":1}\n'

    monkeypatch.setattr(copy_module, "_http_query", fake_query)

    assert copy_module._clickhouse_json(8123, "SELECT 1 value") == [
        {"value": 1}
    ]
    assert seen == ["SELECT 1 value FORMAT JSONEachRow"]


def _pending_row(session_uid: str) -> dict[str, object]:
    return {
        "session_uid": session_uid,
        "revision": 0,
        "state": "open",
        "server_id": 1,
        "domain_id": 7,
        "channel_id": 2,
        "logon_id": "0xabc",
        "logon_source_id": 100,
        "logoff_source_id": None,
        "logon_time_utc": "2026-08-02 01:00:00.000000",
        "logoff_time_utc": None,
        "previous_revision_sha256": "",
        "revision_sha256": "0" * 64,
    }


def test_pending_session_uid_ranges_cover_all_keys_without_overlap() -> None:
    ranges = copy_module._pending_session_uid_ranges()

    assert len(ranges) == copy_module.PENDING_SESSION_UID_RANGE_COUNT == 256
    assert ranges[0] == ("00" + "00" * 15, "01" + "00" * 15)
    assert ranges[-1] == ("ff" + "00" * 15, None)
    for index, (lower, upper) in enumerate(ranges[:-1]):
        assert lower == f"{index:02x}" + "00" * 15
        assert upper == ranges[index + 1][0]


def test_pending_sessions_bounds_each_conflict_and_ranked_query(monkeypatch) -> None:
    conflict_queries: list[str] = []
    ranked_queries: list[str] = []
    monkeypatch.setattr(copy_module, "_session_schema_present", lambda _port: True)

    def fake_http_query(_port: int, query: str) -> bytes:
        conflict_queries.append(query)
        return b"0\n"

    def fake_clickhouse_json(_port: int, query: str) -> list[dict[str, object]]:
        ranked_queries.append(query)
        return []

    monkeypatch.setattr(copy_module, "_http_query", fake_http_query)
    monkeypatch.setattr(copy_module, "_clickhouse_json", fake_clickhouse_json)

    assert copy_module._pending_sessions(18123, "a" * 64) == []

    assert len(conflict_queries) == copy_module.PENDING_SESSION_UID_RANGE_COUNT
    assert len(ranked_queries) == copy_module.PENDING_SESSION_UID_RANGE_COUNT
    for index, query in enumerate(conflict_queries + ranked_queries):
        expected_lower = f"{index % 256:02x}" + "00" * 15
        assert f"session_uid >= unhex('{expected_lower}')" in query
        if index % 256 == 255:
            assert "session_uid < unhex(" not in query
        else:
            expected_upper = f"{(index % 256) + 1:02x}" + "00" * 15
            assert f"session_uid < unhex('{expected_upper}')" in query


def test_pending_sessions_fails_closed_on_a_processed_range_conflict(monkeypatch) -> None:
    conflict_queries: list[str] = []
    monkeypatch.setattr(copy_module, "_session_schema_present", lambda _port: True)

    def fake_http_query(_port: int, query: str) -> bytes:
        conflict_queries.append(query)
        return b"1\n"

    monkeypatch.setattr(copy_module, "_http_query", fake_http_query)
    monkeypatch.setattr(
        copy_module, "_clickhouse_json",
        lambda *_args: pytest.fail("ranked query must not run after a conflict"),
    )

    with pytest.raises(RuntimeError, match="preexisting_warm_session_revision_conflict"):
        copy_module._pending_sessions(18123, "a" * 64)

    assert len(conflict_queries) == 1
    assert "session_uid >= unhex('00000000000000000000000000000000')" in conflict_queries[0]


def test_pending_sessions_merges_ranges_in_stable_global_uid_order(monkeypatch) -> None:
    monkeypatch.setattr(copy_module, "_session_schema_present", lambda _port: True)
    monkeypatch.setattr(copy_module, "_http_query", lambda *_args: b"0\n")

    def fake_clickhouse_json(_port: int, query: str) -> list[dict[str, object]]:
        if "unhex('00000000000000000000000000000000')" in query:
            return [_pending_row("00" * 15 + "02"), _pending_row("00" * 15 + "01")]
        if "unhex('01000000000000000000000000000000')" in query:
            return [_pending_row("01" + "00" * 15)]
        return []

    monkeypatch.setattr(copy_module, "_clickhouse_json", fake_clickhouse_json)

    pending = copy_module._pending_sessions(18123, "a" * 64)

    assert [item.session_uid for item in pending] == [
        "00" * 15 + "01", "00" * 15 + "02", "01" + "00" * 15,
    ]


def test_pending_sessions_stops_at_global_limit_with_only_remaining_probe(monkeypatch) -> None:
    ranked_queries: list[str] = []
    monkeypatch.setattr(copy_module, "MAX_PENDING_SESSIONS", 2)
    monkeypatch.setattr(copy_module, "_session_schema_present", lambda _port: True)
    monkeypatch.setattr(copy_module, "_http_query", lambda *_args: b"0\n")

    def fake_clickhouse_json(_port: int, query: str) -> list[dict[str, object]]:
        ranked_queries.append(query)
        if "unhex('00000000000000000000000000000000')" in query:
            return [_pending_row("00" * 15 + "01"), _pending_row("00" * 15 + "02")]
        if "unhex('01000000000000000000000000000000')" in query:
            return [_pending_row("01" + "00" * 15)]
        raise AssertionError("query continued after the one-row limit probe")

    monkeypatch.setattr(copy_module, "_clickhouse_json", fake_clickhouse_json)

    with pytest.raises(RuntimeError, match="pending_warm_sessions_out_of_bounds"):
        copy_module._pending_sessions(18123, "a" * 64)

    assert [query.rsplit("LIMIT ", 1)[1].split()[0] for query in ranked_queries] == [
        "3", "1",
    ]


def test_pending_sessions_rejects_duplicate_uid_across_merged_ranges(monkeypatch) -> None:
    monkeypatch.setattr(copy_module, "_session_schema_present", lambda _port: True)
    monkeypatch.setattr(copy_module, "_http_query", lambda *_args: b"0\n")

    def fake_clickhouse_json(_port: int, query: str) -> list[dict[str, object]]:
        if "unhex('00000000000000000000000000000000')" in query:
            return [_pending_row("00" * 16)]
        if "unhex('01000000000000000000000000000000')" in query:
            return [_pending_row("00" * 16)]
        return []

    monkeypatch.setattr(copy_module, "_clickhouse_json", fake_clickhouse_json)

    with pytest.raises(RuntimeError, match="duplicate_pending_warm_session_uid"):
        copy_module._pending_sessions(18123, "a" * 64)


def test_executor_reloads_only_the_exact_frozen_event_ids() -> None:
    source = (
        Path(copy_module.__file__).read_text(encoding="utf-8").lower()
    )

    assert "where event.id = any(%s::bigint[])" in source
    assert "where event.id > %s" not in source
    assert "where event_id in ({exact_ids})" in source


def test_copy_rejects_oversized_plan_before_json_materialization(tmp_path: Path) -> None:
    plan = tmp_path / "plan.json"
    plan.write_bytes(b" " * (copy_module.MAX_PLAN_JSON_BYTES + 1))

    with pytest.raises(RuntimeError, match="warm_plan_too_large"):
        copy_module.run(plan, execute=False)


def test_copy_ledger_rejects_oversized_file(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_bytes(b" " * (copy_module.MAX_PROCESSED_LEDGER_BYTES + 1))

    with pytest.raises(RuntimeError, match="processed_package_ledger_too_large"):
        copy_module._processed_declaration_ids_from_ledger(ledger)


@pytest.mark.parametrize("actual_ids", [[101, 101], [101, 101, 102], [101, 101, 101]])
@pytest.mark.parametrize("with_manifest", [False, True])
def test_existing_placement_duplicate_identity_fails_closed(actual_ids, with_manifest):
    expected = [{"id": i, "normalized_hash": "01" * 32,
                 "archive_file": "archive.gz", "archive_line": i} for i in (101, 102)]
    frozen = validate_plan(_plan([_row(101), _row(102)]))
    archive = {"block_sha256_sequence": "a" * 64}
    manifest = _placement_manifest(frozen, archive)
    actual = [{**expected[i - 101], "placement": "unclassified"} for i in actual_ids]
    with pytest.raises(RuntimeError, match="duplicate_warm_batch_event_id"):
        classify_existing(expected, actual, [manifest] if with_manifest else [],
                          _identity(expected), frozen=frozen, archive=archive)


def _placement_manifest(frozen, archive):
    return {
        "batch_identity": frozen["identity_sha256"], "planned_rows": frozen["rows"],
        "first_event_id": frozen["first_event_id"], "last_event_id": frozen["last_event_id"],
        "archive_identity_sha256": archive["block_sha256_sequence"],
        "selection_mode": frozen["selection_mode"],
        "selection_lower_utc": copy_module._format_utc(frozen["selection_lower_utc"]),
        "selection_upper_utc": copy_module._format_utc(frozen["checkpoint_upper_utc"]),
    }


@pytest.mark.parametrize("field,value", [
    ("normalized_hash", "ff" * 32), ("archive_file", "wrong.gz"),
    ("archive_line", 999), ("placement", "wrong"), ("id", 999),
])
def test_existing_placement_still_requires_exact_content(field, value):
    expected = [{"id": 101, "normalized_hash": "01" * 32,
                 "archive_file": "archive.gz", "archive_line": 1}]
    actual = [{**expected[0], "placement": "unclassified", field: value}]
    with pytest.raises(RuntimeError, match="warm_batch_(content|id_set)_mismatch"):
        classify_existing(expected, actual, [], _identity(expected))


@pytest.mark.parametrize("duplicate_phase", ["before", "after", None])
def test_frozen_retry_rejects_duplicate_placements_before_manifest(
    monkeypatch, tmp_path, duplicate_phase,
):
    rows = [_row(101), _row(102)]
    plan = _plan(rows)
    frozen = validate_plan(plan)
    expected = [{"id": r["id"], "normalized_hash": bytes(r["normalized_hash"]).hex(),
                 "archive_file": "archive.gz", "archive_line": i + 1}
                for i, r in enumerate(rows)]
    archive = {"block_sha256_sequence": "a" * 64}
    actual = [{**r, "placement": "unclassified"} for r in expected]
    state = {"rows": [actual[0]], "manifests": [], "staged": [], "writes": []}
    if duplicate_phase == "before":
        state["rows"] = [actual[0], actual[0]]

    class Connection:
        def __enter__(self): return self
        def __exit__(self, *_args): return False
        def execute(self, query):
            assert query == "begin transaction isolation level repeatable read read only"

    monkeypatch.setattr(copy_module, "_connect", Connection)
    monkeypatch.setattr(copy_module, "_source_batch", lambda *_: rows)
    monkeypatch.setattr(copy_module, "_derived_publication_from_frozen_plan", lambda *_: None)
    monkeypatch.setattr(copy_module, "_session_boundaries", lambda *_: [])
    monkeypatch.setattr(copy_module, "_archive_blocks", lambda *_: [])
    monkeypatch.setattr(copy_module, "_archive_placements", lambda *_: (expected, archive))
    monkeypatch.setattr(copy_module, "_existing_rows", lambda *_: list(state["rows"]))
    monkeypatch.setattr(copy_module, "_manifest_rows", lambda *_: list(state["manifests"]))
    monkeypatch.setattr(copy_module, "_session_actual", lambda *_: ([], []))
    monkeypatch.setattr(copy_module, "_stage_rows", lambda _p, _s, rows: state["staged"].extend(rows))
    monkeypatch.setattr(copy_module, "_drop_database", lambda *_: None)

    def query(_port, sql, **_kwargs):
        state["writes"].append(sql)
        if "INSERT INTO" in sql:
            state["rows"] = [actual[0], actual[0]] if duplicate_phase == "after" else actual

    def manifest(_port, current_frozen, current_archive):
        state["manifests"].append(_placement_manifest(current_frozen, current_archive))

    monkeypatch.setattr(copy_module, "_http_query", query)
    monkeypatch.setattr(copy_module, "_write_manifest", manifest)
    for _ in range(2):
        if duplicate_phase:
            with pytest.raises(RuntimeError, match="duplicate_warm_batch_event_id"):
                copy_module.run(tmp_path / "frozen.json", execute=True, port=18123, plan_payload=plan)
            assert state["manifests"] == []
            if duplicate_phase == "before":
                assert state["writes"] == []
        else:
            result = copy_module.run(tmp_path / "frozen.json", execute=True, port=18123, plan_payload=plan)
            assert result["status"] in {"copied_and_verified", "already_published"}
    if duplicate_phase is None:
        assert result["status"] == "already_published"
        assert state["staged"] == [expected[1]]
        assert state["manifests"] == [_placement_manifest(frozen, archive)]


def test_existing_placement_requires_unique_expected_identities():
    row = {"id": 101, "normalized_hash": "01" * 32,
           "archive_file": "archive.gz", "archive_line": 1}
    expected = [row, row]
    with pytest.raises(RuntimeError, match="duplicate_expected_batch_event_id"):
        classify_existing(expected, [{**row, "placement": "unclassified"}], [], _identity(expected))
