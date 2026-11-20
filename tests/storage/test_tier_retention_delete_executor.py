from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import struct
from types import SimpleNamespace

import pytest

from server.sli.storage import tier_retention_delete_executor_runtime as executor
from server.sli.storage import tier_retention_delete_plan_runtime as plan_runtime


def _promotion(archive_requirement: str = "no_archive") -> dict:
    return {
        "archive_requirement": archive_requirement,
        "post_promotion_disposition": "delete_source",
        "read_representation": (
            "derived_only" if archive_requirement == "no_archive" else "archived_atomic"
        ),
        "executable_lifecycle": "existing_warm_then_retention_executor",
    }


def _resolution(archive_requirement: str = "no_archive", fingerprint: str = "a" * 64):
    return SimpleNamespace(
        policy_fingerprint=fingerprint,
        rollup="authentication_session",
        rollup_role="open",
        promotion=_promotion(archive_requirement),
    )


def _persisted_output_identity(row: dict) -> str:
    identity = {
        "batch_identity": row["batch_identity"],
        "candidate_identity_sha256": row["candidate_identity_sha256"],
        "policy_fingerprint": row["policy_fingerprint"],
        "derived_output_digest": row["derived_output_digest"],
        "source_reference_digest": row["source_reference_digest"],
        "manifest_digest": row["manifest_digest"],
        "continuity_declaration_scope_identity": row[
            "continuity_declaration_scope_identity"
        ],
        "continuity_declaration_sha256": row["continuity_declaration_sha256"],
        "payload_sha256": hashlib.sha256(
            str(row["payload_json"]).encode("utf-8")
        ).hexdigest(),
    }
    return hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _promotion_gate(archive_requirement: str = "no_archive") -> dict:
    promotion = _promotion(archive_requirement)
    descriptor_policies = [{
        "event_key": "4624", "rollup_role": "open", "policy_fingerprint": "a" * 64,
    }]
    policy_fingerprint = hashlib.sha256(json.dumps({
        "source": "sli.windows.ad-dc",
        "stream": "Security",
        "descriptor_policies": descriptor_policies,
        "promotion": promotion,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    progress = {
        "contract": "sli.storage-lifecycle-declaration-progress.v1",
        "declaration_ids": [22],
        "scope_identity": "sli.source-capture-continuity.v1:22:" + "a" * 64,
        "declaration_sha256": "a" * 64,
        "candidate_identity_sha256": "2" * 64,
    }
    progress["digest"] = hashlib.sha256(json.dumps(
        progress, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    gate = {
        "contract": "sli.tier-retention-promotion-gate.v1",
        "policy_fingerprint": policy_fingerprint,
        "source": "sli.windows.ad-dc",
        "stream": "Security",
        "event_keys": ["4624"],
        "descriptor_policies": descriptor_policies,
        "archive_requirement": archive_requirement,
        "read_representation": promotion["read_representation"],
        "post_promotion_disposition": promotion["post_promotion_disposition"],
        "executable_lifecycle": promotion["executable_lifecycle"],
        "derived_output_digest": "d" * 64,
        "source_reference_digest": "e" * 64,
        "batch_identity": "1" * 64,
        "candidate_identity_sha256": "2" * 64,
        "manifest_digest": "3" * 64,
        "source_count": 3,
        "observation_count": 1,
        "payload_json": '{"contract":"test"}',
        "published_at_utc": "2026-08-24 10:00:00.000000",
        "continuity_declaration_scope_identity": (
            "sli.source-capture-continuity.v1:22:" + "a" * 64
        ),
        "continuity_declaration_sha256": "a" * 64,
        "declaration_progress": progress,
        "declaration_progress_digest": progress["digest"],
        "read_availability": (
            "derived_only_available" if archive_requirement == "no_archive"
            else "source_archived"
        ),
        "source_references": [
            {"id": event_id, "sha256": (bytes([event_id]) * 32).hex()}
            for event_id in (1, 2, 3)
        ],
    }
    manifest_payload = {
        "contract": "sli.warm-derived-publication.v1",
        "policy_fingerprint": gate["policy_fingerprint"],
        "archive_requirement": gate["archive_requirement"],
        "read_representation": gate["read_representation"],
        "source_ids": [item["id"] for item in gate["source_references"]],
        "candidate_identity_sha256": gate["candidate_identity_sha256"],
        "source_reference_digest": gate["source_reference_digest"],
        "derived_output_digest": gate["derived_output_digest"],
        "declaration_progress_digest": gate["declaration_progress_digest"],
        "readback_required": True,
    }
    gate["manifest_digest"] = hashlib.sha256(json.dumps(
        manifest_payload, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    gate["output_identity"] = _persisted_output_identity(gate)
    return gate


def _persisted_output_row(gate: dict) -> dict:
    return {
        field: gate[field]
        for field in (
            "output_identity", "batch_identity", "candidate_identity_sha256",
            "policy_fingerprint", "derived_output_digest",
            "source_reference_digest", "manifest_digest",
            "continuity_declaration_scope_identity",
            "continuity_declaration_sha256", "source_count",
            "observation_count", "payload_json", "published_at_utc",
        )
    }


def _package(tmp_path: Path) -> Path:
    manifest = tmp_path / "candidates.bin"
    payload = b"".join(
        struct.pack(">Q32s", event_id, bytes([event_id]) * 32)
        for event_id in (1, 2, 3)
    )
    manifest.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    plan = {
        "status": "ready_for_owner_authorization",
        "technical_gate_passed": True,
        "blockers": [],
        "candidate_count": 3,
        "candidate_manifest": {
            "path": str(manifest),
            "format": "big_endian_uint64_event_id_plus_32_byte_normalized_hash",
            "record_bytes": 40,
            "rows": 3,
            "bytes": len(payload),
            "sha256": digest,
            "published": True,
        },
        "postgres": {
            "cutoff_utc": "2026-07-27T12:53:41.319464+07:00",
            "deletion_identity_sha256": digest,
        },
    }
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    return path


def _ready_validated_package(plan_path: Path) -> dict:
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    manifest = Path(plan["candidate_manifest"]["path"])
    return executor._ValidatedPackage(
        {"status": "ready"},
        plan=plan,
        manifest_batch=executor._validated_manifest_batch(manifest.read_bytes()),
    )


def _manifest_batch(event_ids: tuple[int, ...] = (1, 2, 3)):
    return executor._validated_manifest_batch(b"".join(
        struct.pack(">Q32s", event_id, bytes([event_id]) * 32)
        for event_id in event_ids
    ))


def test_executor_rejects_swapped_declaration_progress(monkeypatch) -> None:
    gate = _promotion_gate()
    gate["declaration_progress"] = {
        **gate["declaration_progress"], "declaration_ids": [23],
    }
    monkeypatch.setattr(executor, "resolve_descriptor_retention", lambda *_args: _resolution())

    blockers = executor._promotion_gate_blockers(
        {"promotion_gate": gate}, _manifest_batch(),
    )

    assert "promotion_gate_declaration_progress_invalid" in blockers


def test_transaction_hot_residence_recheck_blocks_forged_recent_cutoff(
    monkeypatch,
) -> None:
    """A package cutoff newer than the transaction policy horizon must not delete."""
    monkeypatch.setattr(
        executor,
        "load_storage_policy",
        lambda: SimpleNamespace(
            db_retention_days=7,
            warm_retention_days=365,
            archive_auto_delete_enabled=False,
        ),
    )

    class Cursor:
        def __init__(self) -> None:
            self.query = ""
            self.params = ()

        def execute(self, query, params) -> None:
            self.query = query
            self.params = params

        def fetchone(self):
            return {"policy_cutoff_utc": datetime(2026, 8, 17, 12, tzinfo=timezone.utc)}

    cur = Cursor()

    with pytest.raises(RuntimeError, match="package_cutoff_inside_transaction_hot_window"):
        executor._recheck_package_cutoff_against_transaction_hot_horizon(
            cur,
            cutoff=datetime(2026, 8, 17, 12, 0, 1, tzinfo=timezone.utc),
        )

    assert "select now()" in cur.query.lower()
    assert cur.params == (7,)


def test_transaction_hot_residence_recheck_allows_exact_or_older_cutoff(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        executor,
        "load_storage_policy",
        lambda: SimpleNamespace(
            db_retention_days=7,
            warm_retention_days=365,
            archive_auto_delete_enabled=False,
        ),
    )

    class Cursor:
        def execute(self, _query, _params) -> None:
            return None

        def fetchone(self):
            return {"policy_cutoff_utc": datetime(2026, 8, 17, 12, tzinfo=timezone.utc)}

    cur = Cursor()
    executor._recheck_package_cutoff_against_transaction_hot_horizon(
        cur, cutoff=datetime(2026, 8, 17, 12, tzinfo=timezone.utc),
    )
    executor._recheck_package_cutoff_against_transaction_hot_horizon(
        cur, cutoff=datetime(2026, 8, 16, 23, 59, 59, tzinfo=timezone.utc),
    )


def test_transaction_hot_residence_recheck_blocks_unavailable_database_time(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        executor,
        "load_storage_policy",
        lambda: SimpleNamespace(
            db_retention_days=7,
            warm_retention_days=365,
            archive_auto_delete_enabled=False,
        ),
    )

    class Cursor:
        def execute(self, _query, _params) -> None:
            return None

        def fetchone(self):
            return None

    with pytest.raises(RuntimeError, match="transaction_hot_horizon_unavailable"):
        executor._recheck_package_cutoff_against_transaction_hot_horizon(
            Cursor(), cutoff=datetime(2026, 8, 17, 12, tzinfo=timezone.utc),
        )


def test_transaction_hot_residence_recheck_blocks_naive_package_cutoff(
    monkeypatch,
) -> None:
    monkeypatch.setattr(executor, "load_storage_policy", lambda: pytest.fail("must not load"))

    with pytest.raises(RuntimeError, match="package_cutoff_timezone_missing"):
        executor._recheck_package_cutoff_against_transaction_hot_horizon(
            object(), cutoff=datetime(2026, 8, 17, 12),
        )


def test_transaction_hot_residence_recheck_blocks_policy_drift(monkeypatch) -> None:
    monkeypatch.setattr(
        executor,
        "load_storage_policy",
        lambda: SimpleNamespace(
            db_retention_days=6,
            warm_retention_days=365,
            archive_auto_delete_enabled=False,
        ),
    )

    with pytest.raises(RuntimeError, match="owner_storage_policy_changed"):
        executor._recheck_package_cutoff_against_transaction_hot_horizon(
            object(), cutoff=datetime(2026, 8, 17, 12, tzinfo=timezone.utc),
        )


def test_execute_blocks_otherwise_valid_forged_cutoff_inside_transaction_hot_window(
    monkeypatch, tmp_path: Path,
) -> None:
    """The executor rejects a signed-looking recent cutoff before DELETE."""
    monkeypatch.setattr(executor, "_windows_account", lambda: executor.APPROVED_OWNER)
    monkeypatch.setattr(executor, "resolve_descriptor_retention", lambda *_args: _resolution())
    plan_path = _package(tmp_path)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["postgres"]["cutoff_utc"] = "2026-08-17T12:00:01+00:00"
    plan["promotion_gate"] = _promotion_gate()
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    validated = executor.validate_package(plan_path)
    assert validated["status"] == "ready"

    monkeypatch.setattr(executor, "validate_package", lambda _path: validated)
    monkeypatch.setattr(executor, "_promotion_gate_blockers", lambda *_args: [])
    monkeypatch.setattr(executor, "_recheck_persisted_promotion_output", lambda _gate: None)
    monkeypatch.setattr(
        executor,
        "_preflight_durable_promotion_continuity",
        lambda _gate, **_kwargs: "verified_before_disposition",
    )
    monkeypatch.setattr(executor, "_recheck_promotion_gate_policy_before_delete", lambda _gate: None)
    monkeypatch.setattr(executor, "_restrictive_references", lambda *_args: {"rows": 0})
    delete_attempts: list[str] = []

    class Cursor:
        def __init__(self) -> None:
            self.query = ""

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, query, _params) -> None:
            self.query = query
            if "delete from events_v2_core" in query:
                delete_attempts.append(query)

        def fetchone(self):
            if "policy_cutoff_utc" in self.query:
                return {"policy_cutoff_utc": datetime(2026, 8, 17, 12, tzinfo=timezone.utc)}
            return {"absent": 0, "hash_mismatch": 0, "inside_cutoff": 0}

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def cursor(self):
            return Cursor()

        def commit(self):
            raise AssertionError("must not commit a recent forged cutoff")

    monkeypatch.setattr(executor, "_connect_write", Conn)

    with pytest.raises(RuntimeError, match="package_cutoff_inside_transaction_hot_window"):
        executor.execute(
            plan_path=plan_path,
            output=tmp_path / "result.json",
            confirmation=executor.CONFIRMATION,
            batch_size=10,
        )

    assert delete_attempts == []


def test_validate_package_accepts_exact_manifest(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(executor, "_windows_account", lambda: executor.APPROVED_OWNER)
    monkeypatch.setattr(
        executor,
        "resolve_descriptor_retention",
        lambda *_args, **_kwargs: _resolution(),
    )
    path = _package(tmp_path)
    plan = json.loads(path.read_text(encoding="utf-8"))
    plan["promotion_gate"] = _promotion_gate()
    path.write_text(json.dumps(plan), encoding="utf-8")

    result = executor.validate_package(path)

    assert result["status"] == "ready"
    assert result["manifest_rows"] == 3
    assert result["blockers"] == []


def test_validate_package_blocks_manifest_tamper(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(executor, "_windows_account", lambda: executor.APPROVED_OWNER)
    plan = _package(tmp_path)
    manifest = Path(json.loads(plan.read_text())["candidate_manifest"]["path"])
    manifest.write_bytes(manifest.read_bytes() + b"x")
    result = executor.validate_package(plan)
    assert result["status"] == "blocked"
    assert "candidate_manifest_size_mismatch" in result["blockers"]
    assert "candidate_manifest_sha256_mismatch" in result["blockers"]


def test_validate_package_blocks_oversized_manifest_without_unbounded_read(
    monkeypatch, tmp_path: Path,
) -> None:
    monkeypatch.setattr(executor, "_windows_account", lambda: executor.APPROVED_OWNER)
    plan_path = _package(tmp_path)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    manifest = Path(plan["candidate_manifest"]["path"])
    oversized = b"x" * ((executor.MAX_BATCH + 1) * executor.RECORD.size)
    manifest.write_bytes(oversized)
    plan["candidate_count"] = executor.MAX_BATCH + 1
    plan["candidate_manifest"].update(
        rows=executor.MAX_BATCH + 1,
        bytes=len(oversized),
        sha256=hashlib.sha256(oversized).hexdigest(),
    )
    plan["postgres"]["deletion_identity_sha256"] = hashlib.sha256(oversized).hexdigest()
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    monkeypatch.setattr(
        Path, "read_bytes",
        lambda _self: pytest.fail("candidate manifest must never use unbounded read_bytes"),
    )

    result = executor.validate_package(plan_path)

    assert result["status"] == "blocked"
    assert "candidate_manifest_too_large" in result["blockers"]
    assert "promotion_manifest_exceeds_atomic_batch" in result["blockers"]


def test_executor_bounded_reader_rejects_same_size_in_place_mutation(
    monkeypatch, tmp_path: Path,
) -> None:
    payload = tmp_path / "plan.json"
    payload.write_bytes(b'{"safe":true}')
    actual_fstat = executor.os.fstat
    expected = payload.stat()
    target_calls = 0

    def changed_mtime(descriptor: int):
        nonlocal target_calls
        current = actual_fstat(descriptor)
        is_target = (current.st_dev, current.st_ino) == (expected.st_dev, expected.st_ino)
        if is_target:
            target_calls += 1
        return SimpleNamespace(
            st_dev=current.st_dev, st_ino=current.st_ino,
            st_size=current.st_size,
            st_mtime_ns=current.st_mtime_ns + (
                1 if is_target and target_calls > 1 else 0
            ),
            st_ctime_ns=current.st_ctime_ns,
        )

    monkeypatch.setattr(executor.os, "fstat", changed_mtime)

    with pytest.raises(RuntimeError, match="bounded_file_changed_during_read"):
        executor._read_file_bounded(payload, max_bytes=1024, too_large="too_large")


def test_validated_manifest_batch_rejects_unsorted_ids(tmp_path: Path) -> None:
    manifest = tmp_path / "bad.bin"
    manifest.write_bytes(
        struct.pack(">Q32s", 2, b"a" * 32)
        + struct.pack(">Q32s", 1, b"b" * 32)
    )
    with pytest.raises(RuntimeError, match="not_strictly_increasing"):
        executor._validated_manifest_batch(manifest.read_bytes())


def test_execute_requires_exact_confirmation(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(executor, "_windows_account", lambda: executor.APPROVED_OWNER)
    with pytest.raises(PermissionError, match="exact owner confirmation"):
        executor.execute(
            plan_path=_package(tmp_path),
            output=tmp_path / "result.json",
            confirmation="yes",
            batch_size=10,
        )


def test_execute_uses_validated_manifest_after_old_path_is_replaced(
    monkeypatch, tmp_path: Path,
) -> None:
    """Replacement after validation cannot change the committed batch."""
    monkeypatch.setattr(executor, "_windows_account", lambda: executor.APPROVED_OWNER)
    monkeypatch.setattr(executor, "resolve_descriptor_retention", lambda *_args: _resolution())
    plan_path = _package(tmp_path)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["promotion_gate"] = _promotion_gate()
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    manifest = Path(plan["candidate_manifest"]["path"])
    validated = executor.validate_package(plan_path)
    assert validated["status"] == "ready"

    def replace_after_validation(_path: Path):
        manifest.write_bytes(b"".join(
            struct.pack(">Q32s", event_id, bytes([event_id]) * 32)
            for event_id in (4, 5, 6)
        ))
        return validated

    monkeypatch.setattr(executor, "validate_package", replace_after_validation)
    monkeypatch.setattr(executor, "_recheck_persisted_promotion_output", lambda _gate: None)
    monkeypatch.setattr(
        executor,
        "_preflight_durable_promotion_continuity",
        lambda _gate, **_kwargs: "verified_before_disposition",
    )
    monkeypatch.setattr(executor, "_restrictive_references", lambda *_args: {"rows": 0})
    deleted_ids: list[tuple[int, ...]] = []

    class Cursor:
        def __init__(self) -> None:
            self.query = ""
            self.params = ()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, query, params):
            self.query = query
            self.params = params

        def fetchone(self):
            if "policy_cutoff_utc" in self.query:
                return {"policy_cutoff_utc": datetime(2026, 8, 17, tzinfo=timezone.utc)}
            if "remaining" in self.query:
                return {"remaining": 0}
            return {"absent": 0, "hash_mismatch": 0, "inside_cutoff": 0}

        def fetchall(self):
            if "delete from events_v2_core" not in self.query:
                return []
            deleted_ids.append(tuple(int(value) for value in self.params[0]))
            return [(event_id,) for event_id in self.params[0]]

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def cursor(self):
            return Cursor()

        def commit(self):
            return None

    monkeypatch.setattr(executor, "_connect_write", Conn)

    result = executor.execute(
        plan_path=plan_path,
        output=tmp_path / "result.json",
        confirmation=executor.CONFIRMATION,
        batch_size=10,
    )

    assert result["status"] == "complete"
    assert deleted_ids == [(1, 2, 3)]


def test_descriptor_promotion_package_binds_the_exact_binary_manifest(
    monkeypatch, tmp_path: Path,
) -> None:
    monkeypatch.setattr(executor, "_windows_account", lambda: executor.APPROVED_OWNER)
    monkeypatch.setattr(
        executor,
        "resolve_descriptor_retention",
        lambda *_args, **_kwargs: _resolution(),
    )
    path = _package(tmp_path)
    plan = json.loads(path.read_text(encoding="utf-8"))
    manifest = Path(plan["candidate_manifest"]["path"])
    plan["promotion_gate"] = _promotion_gate()
    path.write_text(json.dumps(plan), encoding="utf-8")

    result = executor.validate_package(path)

    assert result["status"] == "ready"
    assert result["blockers"] == []
    assert manifest.exists()


def test_missing_promotion_gate_blocks_source_disposition(
    monkeypatch, tmp_path: Path,
) -> None:
    monkeypatch.setattr(executor, "_windows_account", lambda: executor.APPROVED_OWNER)

    result = executor.validate_package(_package(tmp_path))

    assert result["status"] == "blocked"
    assert "promotion_gate_required" in result["blockers"]


def test_non_hex_output_identity_is_rejected_before_clickhouse_query(
    monkeypatch, tmp_path: Path,
) -> None:
    monkeypatch.setattr(executor, "_windows_account", lambda: executor.APPROVED_OWNER)
    monkeypatch.setattr(
        executor,
        "resolve_descriptor_retention",
        lambda *_args, **_kwargs: _resolution(),
    )
    path = _package(tmp_path)
    plan = json.loads(path.read_text(encoding="utf-8"))
    gate = _promotion_gate()
    gate["output_identity"] = "'" + "a" * 63
    plan["promotion_gate"] = gate
    path.write_text(json.dumps(plan), encoding="utf-8")

    result = executor.validate_package(path)

    assert result["status"] == "blocked"
    assert "promotion_gate_output_identity_invalid" in result["blockers"]


def test_promoted_manifest_must_fit_one_atomic_transaction(
    monkeypatch, tmp_path: Path,
) -> None:
    plan_path = _package(tmp_path)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["promotion_gate"] = _promotion_gate()
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    monkeypatch.setattr(executor, "validate_package", _ready_validated_package)
    monkeypatch.setattr(executor, "_promotion_gate_blockers", lambda *_args: [])
    monkeypatch.setattr(executor, "_recheck_persisted_promotion_output", lambda _gate: None)
    write_opened = False

    def connect_write():
        nonlocal write_opened
        write_opened = True
        raise AssertionError("oversized promoted manifest must not open PostgreSQL")

    monkeypatch.setattr(executor, "_connect_write", connect_write)

    with pytest.raises(RuntimeError, match="promotion_manifest_exceeds_atomic_batch"):
        executor.execute(
            plan_path=plan_path,
            output=tmp_path / "result.json",
            confirmation=executor.CONFIRMATION,
            batch_size=2,
        )

    assert write_opened is False


def test_descriptor_policy_drift_blocks_before_any_delete(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(executor, "_windows_account", lambda: executor.APPROVED_OWNER)
    monkeypatch.setattr(
        executor,
        "resolve_descriptor_retention",
        lambda *_args, **_kwargs: _resolution(fingerprint="f" * 64),
    )
    path = _package(tmp_path)
    plan = json.loads(path.read_text(encoding="utf-8"))
    plan["promotion_gate"] = _promotion_gate()
    path.write_text(json.dumps(plan), encoding="utf-8")

    result = executor.validate_package(path)

    assert result["status"] == "blocked"
    assert "promotion_gate_policy_fingerprint_mismatch" in result["blockers"]


def test_promotion_gate_blocks_equal_length_group_fingerprint_tamper(
    monkeypatch, tmp_path: Path,
) -> None:
    monkeypatch.setattr(executor, "_windows_account", lambda: executor.APPROVED_OWNER)
    monkeypatch.setattr(
        executor,
        "resolve_descriptor_retention",
        lambda *_args, **_kwargs: _resolution(),
    )
    path = _package(tmp_path)
    plan = json.loads(path.read_text(encoding="utf-8"))
    plan["promotion_gate"] = _promotion_gate()
    plan["promotion_gate"]["policy_fingerprint"] = "f" * 64
    path.write_text(json.dumps(plan), encoding="utf-8")

    result = executor.validate_package(path)

    assert result["status"] == "blocked"
    assert "promotion_gate_policy_fingerprint_mismatch" in result["blockers"]


@pytest.mark.parametrize(
    "tamper",
    [
        lambda gate: gate.__setitem__("archive_requirement", "archive_required"),
        lambda gate: gate.__setitem__("read_availability", "source_archived"),
        lambda gate: gate["descriptor_policies"][0].__setitem__("rollup_role", "close"),
    ],
    ids=("archive_role", "read_availability", "descriptor_role"),
)
def test_promotion_gate_rejects_role_and_read_state_tamper(monkeypatch, tmp_path: Path, tamper) -> None:
    monkeypatch.setattr(executor, "_windows_account", lambda: executor.APPROVED_OWNER)
    monkeypatch.setattr(executor, "resolve_descriptor_retention", lambda *_args: _resolution())
    path = _package(tmp_path)
    plan = json.loads(path.read_text(encoding="utf-8"))
    gate = _promotion_gate()
    tamper(gate)
    plan["promotion_gate"] = gate
    path.write_text(json.dumps(plan), encoding="utf-8")

    result = executor.validate_package(path)

    assert result["status"] == "blocked"
    assert {
        "promotion_gate_policy_fingerprint_mismatch",
        "promotion_gate_read_availability_mismatch",
    }.intersection(result["blockers"])


def test_persisted_output_policy_fingerprint_tamper_is_rejected(monkeypatch) -> None:
    from server.sli.storage import storage_lifecycle_io
    from server.sli.storage import warm_tier_incremental_copy_runtime as copy_runtime

    gate = _promotion_gate()
    actual = _persisted_output_row(gate)
    actual["policy_fingerprint"] = "f" * 64
    monkeypatch.setattr(storage_lifecycle_io, "_container_port", lambda _container: 8123)
    monkeypatch.setattr(copy_runtime, "_derived_output_actual", lambda *_args: [actual])

    with pytest.raises(RuntimeError, match="promotion_output_policy_fingerprint_mismatch"):
        executor._recheck_persisted_promotion_output(gate)


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        (
            "continuity_declaration_scope_identity",
            "sli.source-capture-continuity.v1:23:" + "a" * 64,
            "promotion_output_continuity_declaration_scope_identity_mismatch",
        ),
        (
            "continuity_declaration_sha256",
            "b" * 64,
            "promotion_output_continuity_declaration_sha256_mismatch",
        ),
    ],
    ids=("scope_only", "sha_only"),
)
def test_persisted_output_continuity_tamper_is_rejected(
    monkeypatch, field: str, value: str, error: str,
) -> None:
    """Removing either continuity comparison must make this regression fail."""
    from server.sli.storage import storage_lifecycle_io
    from server.sli.storage import warm_tier_incremental_copy_runtime as copy_runtime

    gate = _promotion_gate()
    actual = _persisted_output_row(gate)
    actual[field] = value
    monkeypatch.setattr(storage_lifecycle_io, "_container_port", lambda _container: 8123)
    monkeypatch.setattr(copy_runtime, "_derived_output_actual", lambda *_args: [actual])

    with pytest.raises(RuntimeError, match=error):
        executor._recheck_persisted_promotion_output(gate)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("batch_identity", "4" * 64),
        ("candidate_identity_sha256", "5" * 64),
        ("manifest_digest", "6" * 64),
        ("source_count", 4),
        ("observation_count", 2),
        ("payload_json", '{"contract":"tampered"}'),
        ("published_at_utc", "2026-08-24 10:00:01.000000"),
    ],
)
def test_persisted_output_full_row_drift_is_rejected(
    monkeypatch, field: str, value: object,
) -> None:
    from server.sli.storage import storage_lifecycle_io
    from server.sli.storage import warm_tier_incremental_copy_runtime as copy_runtime

    gate = _promotion_gate()
    actual = _persisted_output_row(gate)
    actual[field] = value
    monkeypatch.setattr(storage_lifecycle_io, "_container_port", lambda _container: 8123)
    monkeypatch.setattr(copy_runtime, "_derived_output_actual", lambda *_args: [actual])

    with pytest.raises(RuntimeError, match=f"promotion_output_{field}_mismatch"):
        executor._recheck_persisted_promotion_output(gate)


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        (
            "continuity_declaration_scope_identity",
            "sli.source-capture-continuity.v1:23:" + "a" * 64,
            "promotion_output_continuity_declaration_scope_identity_mismatch",
        ),
        (
            "continuity_declaration_sha256",
            "b" * 64,
            "promotion_output_continuity_declaration_sha256_mismatch",
        ),
    ],
    ids=("scope_only", "sha_only"),
)
def test_isolated_continuity_tamper_blocks_before_executor_disposition(
    monkeypatch, tmp_path: Path, field: str, value: str, error: str,
) -> None:
    """A one-field persisted-output mismatch may not reach source preflight or delete."""
    from server.sli.storage import storage_lifecycle_io
    from server.sli.storage import warm_tier_incremental_copy_runtime as copy_runtime

    plan_path = _package(tmp_path)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    gate = _promotion_gate()
    plan["promotion_gate"] = gate
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    actual = _persisted_output_row(gate)
    actual[field] = value
    preflight_attempts: list[str] = []
    source_write_attempts: list[str] = []
    synthetic_source_rows = [1, 2, 3]

    monkeypatch.setattr(executor, "validate_package", _ready_validated_package)
    monkeypatch.setattr(executor, "_promotion_gate_blockers", lambda *_args: [])
    monkeypatch.setattr(storage_lifecycle_io, "_container_port", lambda _container: 8123)
    monkeypatch.setattr(copy_runtime, "_derived_output_actual", lambda *_args: [actual])
    monkeypatch.setattr(
        executor,
        "_preflight_durable_promotion_continuity",
        lambda _gate, **_kwargs: preflight_attempts.append("unexpected") or "verified_before_disposition",
    )
    monkeypatch.setattr(
        executor,
        "_connect_write",
        lambda: source_write_attempts.append("unexpected"),
    )

    with pytest.raises(
        RuntimeError,
        match=error,
    ):
        executor.execute(
            plan_path=plan_path,
            output=tmp_path / "result.json",
            confirmation=executor.CONFIRMATION,
            batch_size=10,
        )

    assert preflight_attempts == []
    assert source_write_attempts == []
    assert synthetic_source_rows == [1, 2, 3]


def test_durable_continuity_preflight_rejects_interrupted_mixed_disposition(
    monkeypatch,
) -> None:
    """A retry may be all-absent, never a partial fresh provenance proof."""
    gate = _promotion_gate()
    rechecked = False

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, _query, _params):
            return None

        def fetchall(self):
            return [
                {"id": 1, "normalized_hash": (bytes([1]) * 32).hex()},
                {"id": 2, "normalized_hash": (bytes([2]) * 32).hex()},
            ]

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def cursor(self):
            return Cursor()

    def should_not_recheck(*_args, **_kwargs):
        nonlocal rechecked
        rechecked = True

    from server.sli.sources import source_capture_continuity

    monkeypatch.setattr(executor, "_connect_write", Conn)
    monkeypatch.setattr(
        source_capture_continuity,
        "recheck_durable_promotion_continuity",
        should_not_recheck,
    )

    with pytest.raises(RuntimeError, match="promotion_continuity_partial_or_changed_source"):
        executor._preflight_durable_promotion_continuity(
            gate, manifest_batch=_manifest_batch(),
        )

    assert rechecked is False


def test_promoted_executor_rechecks_output_and_records_derived_only_postcondition(
    monkeypatch, tmp_path: Path,
) -> None:
    plan_path = _package(tmp_path)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["promotion_gate"] = _promotion_gate()
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    monkeypatch.setattr(executor, "validate_package", _ready_validated_package)
    monkeypatch.setattr(executor, "_promotion_gate_blockers", lambda *_args: [])
    monkeypatch.setattr(executor, "resolve_descriptor_retention", lambda *_args: _resolution())
    output_checks: list[str] = []
    continuity_cursors: list[object] = []
    monkeypatch.setattr(
        executor, "_recheck_persisted_promotion_output",
        lambda _gate: output_checks.append("readback"),
    )
    monkeypatch.setattr(
        executor, "_preflight_durable_promotion_continuity",
        lambda _gate, *, cur, **_kwargs: (
            continuity_cursors.append(cur) or "verified_before_disposition"
        ),
    )
    monkeypatch.setattr(executor, "_restrictive_references", lambda *_args: {"rows": 0})
    monkeypatch.setattr(
        executor,
        "_recheck_archive_required_promotion",
        lambda *_args: pytest.fail("no_archive disposition must never open or require an archive"),
    )
    executed: list[tuple[str, tuple]] = []

    class Cursor:
        def __init__(self) -> None:
            self.query = ""

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, query, _params):
            self.query = query
            executed.append((query, _params))

        def fetchone(self):
            if "policy_cutoff_utc" in self.query:
                return {"policy_cutoff_utc": datetime(2026, 8, 17, tzinfo=timezone.utc)}
            if "remaining" in self.query:
                return {"remaining": 0}
            return {"absent": 0, "hash_mismatch": 0, "inside_cutoff": 0}

        def fetchall(self):
            if "delete from events_v2_core" in self.query:
                return [(1,), (2,), (3,)]
            return []

    class Conn:
        def __init__(self) -> None:
            self.write_cursor = Cursor()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def cursor(self):
            return self.write_cursor

        def commit(self):
            return None

    connection = Conn()
    monkeypatch.setattr(executor, "_connect_write", lambda: connection)
    result = executor.execute(
        plan_path=plan_path,
        output=tmp_path / "result.json",
        confirmation=executor.CONFIRMATION,
        batch_size=10,
    )

    assert result["status"] == "complete"
    assert result["deleted_rows"] == 3
    gate = plan["promotion_gate"]
    assert gate["archive_requirement"] == "no_archive"
    assert gate["post_promotion_disposition"] == "delete_source"
    assert continuity_cursors == [connection.write_cursor]
    assert output_checks == ["readback", "readback", "readback"]
    assert result["post_delete_verifications"] == [{
        "hot_source_ids_absent": True,
        "persisted_output_verified": True,
        "read_availability": "derived_only_available",
        "atomic_evidence_available": False,
    }]
    delete_query, delete_params = next(
        item for item in executed if "delete from events_v2_core" in item[0]
    )
    assert "event.id=manifest_row.event_id" in delete_query
    assert "event.normalized_hash=manifest_row.normalized_hash" in delete_query
    assert "event.time_created_utc < %s" in delete_query
    assert delete_params == (
        [1, 2, 3], [bytes([1]) * 32, bytes([2]) * 32, bytes([3]) * 32],
        datetime(2026, 7, 27, 5, 53, 41, 319464, tzinfo=timezone.utc),
    )
    sql = "\n".join(query for query, _params in executed).casefold()
    assert all(
        forbidden not in sql
        for forbidden in ("raw_log_files", "evtx", "unlink", "delete from archive")
    )


def test_post_delete_verification_blocks_commit_on_policy_drift_after_predelete_check(
    monkeypatch, tmp_path: Path,
) -> None:
    """Policy fingerprint drift between the pre-delete exact recheck and the
    post-delete pre-commit verification must block commit, not just a change
    in read availability."""
    plan_path = _package(tmp_path)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["promotion_gate"] = _promotion_gate()
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    monkeypatch.setattr(executor, "validate_package", _ready_validated_package)
    monkeypatch.setattr(executor, "_promotion_gate_blockers", lambda *_args: [])
    resolver_calls = {"count": 0}

    def resolver(*_args):
        resolver_calls["count"] += 1
        if resolver_calls["count"] == 1:
            return _resolution()
        return _resolution(fingerprint="f" * 64)

    monkeypatch.setattr(executor, "resolve_descriptor_retention", resolver)
    monkeypatch.setattr(executor, "_recheck_persisted_promotion_output", lambda _gate: None)
    monkeypatch.setattr(
        executor, "_preflight_durable_promotion_continuity",
        lambda _gate, *, cur, **_kwargs: "verified_before_disposition",
    )
    monkeypatch.setattr(executor, "_restrictive_references", lambda *_args: {"rows": 0})

    class Cursor:
        def __init__(self) -> None:
            self.query = ""

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, query, _params):
            self.query = query

        def fetchone(self):
            if "policy_cutoff_utc" in self.query:
                return {"policy_cutoff_utc": datetime(2026, 8, 17, tzinfo=timezone.utc)}
            if "remaining" in self.query:
                return {"remaining": 0}
            return {"absent": 0, "hash_mismatch": 0, "inside_cutoff": 0}

        def fetchall(self):
            if "delete from events_v2_core" in self.query:
                return [(1,), (2,), (3,)]
            return []

    class Conn:
        def __init__(self) -> None:
            self.write_cursor = Cursor()
            self.commits = 0

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def cursor(self):
            return self.write_cursor

        def commit(self):
            self.commits += 1

    connection = Conn()
    monkeypatch.setattr(executor, "_connect_write", lambda: connection)

    with pytest.raises(RuntimeError, match="promotion_gate_policy_fingerprint_mismatch"):
        executor.execute(
            plan_path=plan_path,
            output=tmp_path / "result.json",
            confirmation=executor.CONFIRMATION,
            batch_size=10,
        )

    assert connection.commits == 0
    assert resolver_calls["count"] == 2


def test_archive_required_promotion_rechecks_archive_proof_for_atomic_manifest(
    monkeypatch, tmp_path: Path,
) -> None:
    plan_path = _package(tmp_path)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["promotion_gate"] = _promotion_gate("archive_required")
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    monkeypatch.setattr(executor, "validate_package", _ready_validated_package)
    monkeypatch.setattr(executor, "_promotion_gate_blockers", lambda *_args: [])
    monkeypatch.setattr(
        executor, "resolve_descriptor_retention", lambda *_args: _resolution("archive_required"),
    )
    monkeypatch.setattr(executor, "_recheck_persisted_promotion_output", lambda _gate: None)
    monkeypatch.setattr(
        executor, "_preflight_durable_promotion_continuity",
        lambda _gate, *, cur, **_kwargs: "verified_before_disposition",
    )
    monkeypatch.setattr(executor, "_restrictive_references", lambda *_args: {"rows": 0})
    archive_checks: list[list[int]] = []

    def verify_warm(rows):
        archive_checks.append([int(row["id"]) for row in rows])
        return {
            "missing": 0,
            "hash_mismatches": 0,
            "archive_paths_missing": 0,
        }

    monkeypatch.setattr(plan_runtime, "verify_warm", verify_warm)

    class Cursor:
        def __init__(self) -> None:
            self.query = ""

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, query, _params):
            self.query = query

        def fetchone(self):
            if "policy_cutoff_utc" in self.query:
                return {"policy_cutoff_utc": datetime(2026, 8, 17, tzinfo=timezone.utc)}
            if "remaining" in self.query:
                return {"remaining": 0}
            return {"absent": 0, "hash_mismatch": 0, "inside_cutoff": 0}

        def fetchall(self):
            if "delete from events_v2_core" in self.query:
                return [(1,), (2,), (3,)]
            return []

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def cursor(self):
            return Cursor()

        def commit(self):
            return None

    monkeypatch.setattr(executor, "_connect_write", Conn)

    result = executor.execute(
        plan_path=plan_path,
        output=tmp_path / "result.json",
        confirmation=executor.CONFIRMATION,
        batch_size=10,
    )

    assert result["status"] == "complete"
    assert archive_checks == [[1, 2, 3], [1, 2, 3], [1, 2, 3]]


def test_promoted_executor_is_idempotent_when_the_exact_manifest_is_already_absent(
    monkeypatch, tmp_path: Path,
) -> None:
    plan_path = _package(tmp_path)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["promotion_gate"] = _promotion_gate()
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    monkeypatch.setattr(executor, "validate_package", _ready_validated_package)
    monkeypatch.setattr(executor, "_promotion_gate_blockers", lambda *_args: [])
    monkeypatch.setattr(executor, "resolve_descriptor_retention", lambda *_args: _resolution())
    monkeypatch.setattr(executor, "_restrictive_references", lambda *_args: {"rows": 0})
    readbacks: list[str] = []
    monkeypatch.setattr(
        executor,
        "_recheck_persisted_promotion_output",
        lambda _gate: readbacks.append("verified"),
    )
    remaining = {1, 2, 3}
    delete_attempts: list[tuple[int, ...]] = []
    monkeypatch.setattr(
        executor, "_preflight_durable_promotion_continuity",
        lambda _gate, *, cur, **_kwargs: (
            "verified_before_disposition"
            if remaining else "already_absent_exact_retry"
        ),
    )

    class Cursor:
        def __init__(self) -> None:
            self.query = ""
            self.params = ()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, query, params):
            self.query = query
            self.params = params

        def fetchone(self):
            if "policy_cutoff_utc" in self.query:
                return {"policy_cutoff_utc": datetime(2026, 8, 17, tzinfo=timezone.utc)}
            ids = [int(value) for value in self.params[0]]
            if "remaining" in self.query:
                return {"remaining": len(remaining.intersection(ids))}
            return {
                "absent": len([event_id for event_id in ids if event_id not in remaining]),
                "hash_mismatch": 0,
                "inside_cutoff": 0,
            }

        def fetchall(self):
            if "delete from events_v2_core" not in self.query:
                return []
            ids = [int(value) for value in self.params[0]]
            deleted = [(event_id,) for event_id in ids if event_id in remaining]
            delete_attempts.append(tuple(ids))
            remaining.difference_update(ids)
            return deleted

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def cursor(self):
            return Cursor()

        def commit(self):
            return None

    monkeypatch.setattr(executor, "_connect_write", Conn)

    first = executor.execute(
        plan_path=plan_path,
        output=tmp_path / "first.json",
        confirmation=executor.CONFIRMATION,
        batch_size=10,
    )
    second = executor.execute(
        plan_path=plan_path,
        output=tmp_path / "second.json",
        confirmation=executor.CONFIRMATION,
        batch_size=10,
    )

    assert first["deleted_rows"] == 3
    assert second["deleted_rows"] == 0
    assert second["already_absent_rows"] == 3
    assert remaining == set()
    assert delete_attempts == [(1, 2, 3)]
    assert len(readbacks) == 4


@pytest.mark.parametrize(
    ("blockers", "readback_error", "expected"),
    [
        ([], "promotion_output_missing_or_duplicate", "promotion_output_missing_or_duplicate"),
        (["promotion_gate_descriptor_policy_drift"], None, "promotion_gate_recheck_blocked"),
    ],
    ids=("persisted_readback_failure", "policy_drift"),
)
def test_promotion_failure_preserves_source_before_opening_write_connection(
    monkeypatch, tmp_path: Path, blockers, readback_error: str | None, expected: str,
) -> None:
    plan_path = _package(tmp_path)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["promotion_gate"] = _promotion_gate()
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    monkeypatch.setattr(executor, "validate_package", _ready_validated_package)
    monkeypatch.setattr(executor, "_promotion_gate_blockers", lambda *_args: blockers)

    def fail_readback(_gate):
        if readback_error:
            raise RuntimeError(readback_error)

    monkeypatch.setattr(executor, "_recheck_persisted_promotion_output", fail_readback)
    write_opened = False

    def connect_write():
        nonlocal write_opened
        write_opened = True
        raise AssertionError("source must remain untouched")

    monkeypatch.setattr(executor, "_connect_write", connect_write)

    with pytest.raises(RuntimeError, match=expected):
        executor.execute(
            plan_path=plan_path,
            output=tmp_path / "result.json",
            confirmation=executor.CONFIRMATION,
            batch_size=10,
        )

    assert write_opened is False


def test_tampered_package_preserves_source_before_executor_opens_write_connection(
    monkeypatch, tmp_path: Path,
) -> None:
    monkeypatch.setattr(executor, "_windows_account", lambda: executor.APPROVED_OWNER)
    plan_path = _package(tmp_path)
    manifest = Path(json.loads(plan_path.read_text(encoding="utf-8"))["candidate_manifest"]["path"])
    manifest.write_bytes(manifest.read_bytes() + b"tamper")
    write_opened = False

    def connect_write():
        nonlocal write_opened
        write_opened = True
        raise AssertionError("source must remain untouched")

    monkeypatch.setattr(executor, "_connect_write", connect_write)

    with pytest.raises(RuntimeError, match="retention_package_preflight_blocked"):
        executor.execute(
            plan_path=plan_path,
            output=tmp_path / "result.json",
            confirmation=executor.CONFIRMATION,
            batch_size=10,
        )

    assert write_opened is False


def test_descriptor_policy_drift_after_preflight_blocks_before_delete(
    monkeypatch, tmp_path: Path,
) -> None:
    """A policy change landing after the outer preflight but before the
    delete must still be caught, right after FOR UPDATE + durable
    continuity and immediately before DELETE."""
    plan_path = _package(tmp_path)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["promotion_gate"] = _promotion_gate()
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    monkeypatch.setattr(executor, "validate_package", _ready_validated_package)
    monkeypatch.setattr(executor, "_promotion_gate_blockers", lambda *_args: [])
    monkeypatch.setattr(
        executor, "resolve_descriptor_retention",
        lambda *_args, **_kwargs: _resolution(fingerprint="f" * 64),
    )
    monkeypatch.setattr(executor, "_recheck_persisted_promotion_output", lambda _gate: None)
    monkeypatch.setattr(
        executor, "_preflight_durable_promotion_continuity",
        lambda _gate, *, cur, **_kwargs: "verified_before_disposition",
    )
    monkeypatch.setattr(executor, "_restrictive_references", lambda *_args: {"rows": 0})
    delete_attempts: list[str] = []

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, query, _params):
            if "delete from events_v2_core" in query:
                delete_attempts.append(query)

        def fetchone(self):
            return {"remaining": 0, "absent": 0, "hash_mismatch": 0, "inside_cutoff": 0}

        def fetchall(self):
            return []

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def cursor(self):
            return Cursor()

        def commit(self):
            raise AssertionError("must not commit after policy drift")

    monkeypatch.setattr(executor, "_connect_write", Conn)

    with pytest.raises(RuntimeError, match="promotion_gate_policy_fingerprint_mismatch"):
        executor.execute(
            plan_path=plan_path,
            output=tmp_path / "result.json",
            confirmation=executor.CONFIRMATION,
            batch_size=10,
        )

    assert delete_attempts == []


def test_archive_proof_missing_immediately_before_delete_blocks_and_preserves_source(
    monkeypatch, tmp_path: Path,
) -> None:
    plan_path = _package(tmp_path)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["promotion_gate"] = _promotion_gate("archive_required")
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    monkeypatch.setattr(executor, "validate_package", _ready_validated_package)
    monkeypatch.setattr(executor, "_promotion_gate_blockers", lambda *_args: [])
    monkeypatch.setattr(
        executor, "resolve_descriptor_retention",
        lambda *_args, **_kwargs: _resolution("archive_required"),
    )
    monkeypatch.setattr(executor, "_recheck_persisted_promotion_output", lambda _gate: None)
    monkeypatch.setattr(
        executor, "_preflight_durable_promotion_continuity",
        lambda _gate, *, cur, **_kwargs: "verified_before_disposition",
    )
    monkeypatch.setattr(executor, "_restrictive_references", lambda *_args: {"rows": 0})
    calls = {"count": 0}

    def verify_warm(_rows):
        calls["count"] += 1
        if calls["count"] == 1:
            return {"missing": 0, "hash_mismatches": 0, "archive_paths_missing": 0}
        return {"missing": 1, "hash_mismatches": 0, "archive_paths_missing": 0}

    monkeypatch.setattr(plan_runtime, "verify_warm", verify_warm)
    delete_attempts: list[str] = []

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, query, _params):
            if "delete from events_v2_core" in query:
                delete_attempts.append(query)

        def fetchone(self):
            return {"remaining": 0, "absent": 0, "hash_mismatch": 0, "inside_cutoff": 0}

        def fetchall(self):
            return []

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def cursor(self):
            return Cursor()

        def commit(self):
            raise AssertionError("must not commit after archive proof failure")

    monkeypatch.setattr(executor, "_connect_write", Conn)

    with pytest.raises(RuntimeError, match="promotion_archive_proof_recheck_failed"):
        executor.execute(
            plan_path=plan_path,
            output=tmp_path / "result.json",
            confirmation=executor.CONFIRMATION,
            batch_size=10,
        )

    assert delete_attempts == []
    assert calls["count"] == 2


def test_archive_proof_disappears_after_delete_rolls_back_before_commit(
    monkeypatch, tmp_path: Path,
) -> None:
    plan_path = _package(tmp_path)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["promotion_gate"] = _promotion_gate("archive_required")
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    monkeypatch.setattr(executor, "validate_package", _ready_validated_package)
    monkeypatch.setattr(executor, "_promotion_gate_blockers", lambda *_args: [])
    monkeypatch.setattr(
        executor, "resolve_descriptor_retention",
        lambda *_args, **_kwargs: _resolution("archive_required"),
    )
    monkeypatch.setattr(executor, "_recheck_persisted_promotion_output", lambda _gate: None)
    monkeypatch.setattr(
        executor, "_preflight_durable_promotion_continuity",
        lambda _gate, *, cur, **_kwargs: "verified_before_disposition",
    )
    monkeypatch.setattr(executor, "_restrictive_references", lambda *_args: {"rows": 0})
    calls = {"count": 0}

    def verify_warm(_rows):
        calls["count"] += 1
        if calls["count"] <= 2:
            return {"missing": 0, "hash_mismatches": 0, "archive_paths_missing": 0}
        return {"missing": 0, "hash_mismatches": 0, "archive_paths_missing": 3}

    monkeypatch.setattr(plan_runtime, "verify_warm", verify_warm)
    committed = False

    class Cursor:
        def __init__(self) -> None:
            self.query = ""

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, query, _params):
            self.query = query

        def fetchone(self):
            if "policy_cutoff_utc" in self.query:
                return {"policy_cutoff_utc": datetime(2026, 8, 17, tzinfo=timezone.utc)}
            if "remaining" in self.query:
                return {"remaining": 0}
            return {"absent": 0, "hash_mismatch": 0, "inside_cutoff": 0}

        def fetchall(self):
            if "delete from events_v2_core" in self.query:
                return [(1,), (2,), (3,)]
            return []

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def cursor(self):
            return Cursor()

        def commit(self):
            nonlocal committed
            committed = True

    monkeypatch.setattr(executor, "_connect_write", Conn)

    with pytest.raises(RuntimeError, match="promotion_archive_proof_recheck_failed"):
        executor.execute(
            plan_path=plan_path,
            output=tmp_path / "result.json",
            confirmation=executor.CONFIRMATION,
            batch_size=10,
        )

    assert committed is False
    assert calls["count"] == 3
