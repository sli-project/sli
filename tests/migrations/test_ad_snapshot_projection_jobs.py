from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from server.sli.sources import ad_snapshot_projection
from server.sli.sources.ad_snapshot_projection import (
    PROJECTION_ALLOWLIST,
    ProjectionConflictError,
    claim_projection_receipts,
    create_projection_receipts,
    project_exact_manifest,
    record_projection_result,
)
from server.ad_context.repository import publish_snapshot_manifest


ROOT = Path(__file__).resolve().parents[2]
MANIFEST_ID = "00000000-0000-4000-8000-000000000501"


def _canonical(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def test_static_allowlist_is_report_specific_and_excludes_radius_semantic_and_vpn() -> None:
    assert PROJECTION_ALLOWLIST == {
        "ad.users.v2": 1,
        "ad.computers.v6": 1,
        "ad.gpo.v2": 1,
        "ad.state": 1,
    }
    assert not {"vpn.audit", "radius", "semantic"}.intersection(PROJECTION_ALLOWLIST)


def test_only_committed_manifest_creates_one_receipt_per_allowlisted_version() -> None:
    assert create_projection_receipts(MANIFEST_ID, manifest_state="collecting") == ()
    assert create_projection_receipts(MANIFEST_ID, manifest_state="rejected") == ()
    receipts = create_projection_receipts(MANIFEST_ID, manifest_state="committed")
    assert len(receipts) == 4
    assert len({(row["manifest_id"], row["projection_key"], row["projection_version"]) for row in receipts}) == 4
    assert {row["status"] for row in receipts} == {"pending"}


class Cursor:
    def __init__(self, existing=None):
        self.existing = existing
        self.executed: list[tuple[str, object]] = []
        self.phase = ""

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))
        folded = " ".join(sql.casefold().split())
        if "from ad_snapshot_manifests" in folded:
            self.phase = "manifest"
        elif "ad_snapshot_projection_receipts" in folded and "returning" in folded:
            self.phase = "claim"
        else:
            self.phase = ""

    def fetchone(self):
        return self.existing if self.phase == "manifest" else None

    def fetchall(self):
        return []


class Connection:
    def __init__(self, cursor: Cursor):
        self.value = cursor

    def cursor(self):
        return self.value


def _manifest():
    from tests.migrations.test_ad_snapshot_manifest import _manifest as base
    return base()


def _resolver(member):
    from tests.migrations.test_ad_snapshot_manifest import _resolver as base
    return base(member)


def test_publish_commits_manifest_sources_and_receipts_in_one_cursor_scope() -> None:
    cursor = Cursor()
    result = publish_snapshot_manifest(Connection(cursor), _manifest(), resolve_source=_resolver)
    sql = "\n".join(statement.casefold() for statement, _ in cursor.executed)
    assert result["replayed"] == 0
    assert "insert into ad_snapshot_manifests" in sql
    assert "insert into ad_snapshot_manifest_sources" in sql
    assert sql.count("insert into ad_snapshot_projection_receipts") == 4


def test_claim_is_skip_locked_lease_bounded_and_attempt_bounded() -> None:
    cursor = Cursor()
    claim_projection_receipts(Connection(cursor), worker_id="shadow-test", limit=3, lease_seconds=60, max_attempts=4)
    sql, params = cursor.executed[-1]
    folded = " ".join(sql.casefold().split())
    assert "for update skip locked" in folded
    assert "attempt_count < %s" in folded
    assert "lease_expires_at" in folded
    assert "limit %s" in folded
    assert 4 in params and 3 in params and 60 in params
    with pytest.raises(ValueError):
        claim_projection_receipts(Connection(Cursor()), worker_id="x", limit=0)


def test_claim_can_be_scoped_to_one_exact_manifest() -> None:
    cursor = Cursor()
    claim_projection_receipts(
        Connection(cursor), worker_id="coordinator", manifest_id=MANIFEST_ID
    )

    sql, params = cursor.executed[-1]
    assert "receipt.manifest_id=%s" in "".join(sql.casefold().split())
    assert MANIFEST_ID in params


def test_expired_running_claim_is_reclaimed_after_worker_crash_with_attempt_bound() -> None:
    cursor = Cursor()
    claim_projection_receipts(
        Connection(cursor), worker_id="replacement-worker", max_attempts=4
    )
    sql, params = cursor.executed[-1]
    folded = " ".join(sql.casefold().split())

    assert "status in ('pending','failed')" in folded
    assert "or (status='running' and lease_expires_at <= now())" in folded
    assert "attempt_count < %s" in folded
    assert params[0] == 4


def test_completion_updates_only_receipt_hashes_and_failure_is_retryable() -> None:
    cursor = OutputCursor()
    claim = {
        "manifest_id": MANIFEST_ID,
        "projection_key": "ad.users.v2",
        "projection_version": 1,
        "lease_owner": "shadow-test",
    }
    output = {"durable": "exact"}
    output_sha256 = _canonical(output)
    cursor.output = {
        "manifest_id": MANIFEST_ID,
        "projection_key": "ad.users.v2",
        "projection_version": 1,
        "input_sha256": "a" * 64,
        "output_sha256": output_sha256,
        "output_identity": f"{MANIFEST_ID}:ad.users.v2:v1",
        "payload_json": output,
    }
    record_projection_result(
        Connection(cursor), claim=claim,
        result={
            "input_sha256": "a" * 64,
            "output_sha256": output_sha256,
            "output_identity": f"{MANIFEST_ID}:ad.users.v2:v1",
        },
    )
    sql, params = cursor.executed[-1]
    assert "update ad_snapshot_projection_receipts" in sql.casefold()
    assert "status='completed'" in sql.casefold()
    assert "decode(%s,'hex')" in sql.casefold()
    assert "users_report_v2_snapshots" not in sql.casefold()
    assert f"{MANIFEST_ID}:ad.users.v2:v1" in params

    failed = Cursor()
    record_projection_result(
        Connection(failed), claim=claim, result={"error": "RuntimeError:isolated"}
    )
    failed_sql, failed_params = failed.executed[-1]
    assert "status='failed'" in failed_sql.casefold()
    assert "lease_expires_at=null" in failed_sql.casefold()
    assert "RuntimeError:isolated" in failed_params


def test_exact_manifest_projectors_receive_declared_ids_and_hashes_without_latest_query() -> None:
    members = {
        "users_v2": {"family": "users_v2", "source_id": "42", "payload_sha256": "a" * 64},
        "computers_v6": {"family": "computers_v6", "source_id": "00000000-0000-4000-8000-000000000502", "payload_sha256": "b" * 64},
        "gpo_v2": {"family": "gpo_v2", "source_id": "00000000-0000-4000-8000-000000000503", "payload_sha256": "c" * 64},
        "ad_context_base": {"family": "ad_context_base", "source_id": "00000000-0000-4000-8000-000000000504", "payload_sha256": "d" * 64},
    }
    seen: list[tuple[str, str, str]] = []

    def load_exact(family, source_id, payload_sha256):
        seen.append((family, source_id, payload_sha256))
        return {"family": family, "source_id": source_id}

    result = project_exact_manifest(
        {"manifest_id": MANIFEST_ID, "manifest_sha256": "e" * 64, "members": members},
        load_exact=load_exact,
    )
    assert set(result) == set(PROJECTION_ALLOWLIST)
    assert set(seen) == {(m["family"], m["source_id"], m["payload_sha256"]) for m in members.values()}
    from inspect import getsource
    from server.ad_context.repository import load_exact_projection_source
    exact_loader = getsource(load_exact_projection_source).casefold()
    assert "order by" not in exact_loader and " latest" not in exact_loader
    assert all(set(value) == {"input_sha256", "output_sha256", "output_identity"} for value in result.values())


def test_ad_state_exact_projection_is_deterministic() -> None:
    manifest = {
        "manifest_id": MANIFEST_ID,
        "manifest_sha256": "e" * 64,
        "members": {
            "ad_context_base": {
                "family": "ad_context_base",
                "source_id": "00000000-0000-4000-8000-000000000509",
                "payload_sha256": "d" * 64,
            }
        },
    }
    exact_state = {"run_id": "00000000-0000-4000-8000-000000000509", "status": "completed"}
    first = project_exact_manifest(
        manifest, load_exact=lambda *_args: exact_state,
        projection_keys=("ad.state",),
    )
    second = project_exact_manifest(
        manifest, load_exact=lambda *_args: dict(reversed(list(exact_state.items()))),
        projection_keys=("ad.state",),
    )
    assert first["ad.state"]["output_sha256"] == second["ad.state"]["output_sha256"]


def test_one_projector_failure_is_independent_and_never_targets_active_snapshot_tables() -> None:
    manifest = {
        "manifest_id": MANIFEST_ID,
        "manifest_sha256": "f" * 64,
        "members": {
            "users_v2": {"family": "users_v2", "source_id": "7", "payload_sha256": "a" * 64},
            "computers_v6": {"family": "computers_v6", "source_id": "00000000-0000-4000-8000-000000000505", "payload_sha256": "b" * 64},
            "gpo_v2": {"family": "gpo_v2", "source_id": "00000000-0000-4000-8000-000000000506", "payload_sha256": "c" * 64},
            "ad_context_base": {"family": "ad_context_base", "source_id": "00000000-0000-4000-8000-000000000507", "payload_sha256": "d" * 64},
        },
    }

    def load_exact(family, *_args):
        if family == "users_v2":
            raise RuntimeError("isolated")
        return {"family": family}

    result = project_exact_manifest(manifest, load_exact=load_exact)
    assert result["ad.users.v2"]["error"] == "RuntimeError:isolated"
    assert result["ad.computers.v6"]["output_sha256"] == _canonical({"family": "computers_v6"})
    source = (ROOT / "server/sli/sources/ad_snapshot_projection.py").read_text(encoding="utf-8").casefold()
    assert "users_report_v2_snapshots" not in source
    assert "computers_report_v6_snapshots" not in source
    assert "gpo_report_v2_source_snapshots" not in source


def test_conflicting_receipt_replay_fails_closed() -> None:
    with pytest.raises(ProjectionConflictError):
        create_projection_receipts(
            MANIFEST_ID,
            manifest_state="committed",
            existing={("ad.users.v2", 1): {"manifest_id": MANIFEST_ID, "input_sha256": "0" * 64}},
            manifest_sha256="1" * 64,
        )


def test_migration_extends_unaccepted_121_additively_and_rollback_refuses_receipt_rows() -> None:
    forward = (ROOT / "config/postgres_migrations/121_ad_snapshot_manifest_foundation.sql").read_text(encoding="utf-8").casefold()
    rollback = (ROOT / "config/postgres_migrations/121_ad_snapshot_manifest_foundation.rollback.sql").read_text(encoding="utf-8").casefold()
    assert "create table if not exists ad_snapshot_projection_receipts" in forward
    assert "primarykey(manifest_id,projection_key,projection_version)" in forward.replace(" ", "")
    assert "attempt_count" in forward and "lease_expires_at" in forward
    assert "projection_keyin('ad.users.v2','ad.computers.v6','ad.gpo.v2','ad.state')" in forward.replace(" ", "")
    assert "import_path" not in forward and "command" not in forward
    assert "refusing rollback" in rollback and "ad_snapshot_projection_receipts" in rollback
    assert rollback.index("raise exception") < rollback.index("drop table if exists ad_snapshot_projection_receipts")
    assert "delete from ad_snapshot_projection_receipts" not in rollback


class OutputCursor:
    def __init__(self) -> None:
        self.executed: list[tuple[str, object]] = []
        self.output: dict[str, object] | None = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))
        folded = " ".join(sql.casefold().split())
        if "insert into ad_snapshot_projection_outputs" in folded:
            assert params is not None
            self.output = {
                "manifest_id": params[0],
                "projection_key": params[1],
                "projection_version": params[2],
                "input_sha256": bytes(params[3]).hex(),
                "output_sha256": bytes(params[4]).hex(),
                "output_identity": params[5],
                "payload_json": json.loads(params[6]),
            }

    def fetchone(self):
        return self.output


def test_projection_output_is_persisted_and_exactly_read_back_before_completion() -> None:
    cursor = OutputCursor()
    output = {"source": "exact", "items": ["one"]}

    result = ad_snapshot_projection.persist_projection_output(
        Connection(cursor),
        manifest_id=MANIFEST_ID,
        projection_key="ad.users.v2",
        projection_version=1,
        input_sha256="a" * 64,
        output=output,
    )

    assert result == {
        "input_sha256": "a" * 64,
        "output_sha256": _canonical(output),
        "output_identity": f"{MANIFEST_ID}:ad.users.v2:v1",
    }
    sql = "\n".join(statement.casefold() for statement, _ in cursor.executed)
    assert "insert into ad_snapshot_projection_outputs" in sql
    assert "onconflict(manifest_id,projection_key,projection_version)donothing" in sql.replace(" ", "")
    assert "from ad_snapshot_projection_outputs" in sql
    assert "users_report_v2_snapshots" not in sql


def test_claim_completion_uses_one_exact_source_and_persists_output_first() -> None:
    cursor = OutputCursor()
    claim = {
        "manifest_id": MANIFEST_ID,
        "projection_key": "ad.state",
        "projection_version": 1,
        "lease_owner": "coordinator",
    }
    manifest = {
        "manifest_id": MANIFEST_ID,
        "manifest_sha256": "f" * 64,
        "members": {
            "ad_context_base": {
                "source_id": "source-base-1",
                "payload_sha256": "b" * 64,
            }
        },
    }
    exact_calls: list[tuple[str, str, str]] = []
    persisted: list[dict[str, object]] = []

    def load_exact(family, source_id, payload_sha256):
        exact_calls.append((family, source_id, payload_sha256))
        return {"source": "base", "source_id": source_id}

    def persist_output(_conn, **kwargs):
        persisted.append(kwargs)
        result = {
            "input_sha256": kwargs["input_sha256"],
            "output_sha256": _canonical(kwargs["output"]),
            "output_identity": f"{MANIFEST_ID}:ad.state:v1",
        }
        cursor.output = {
            "manifest_id": MANIFEST_ID,
            "projection_key": "ad.state",
            "projection_version": 1,
            **result,
            "payload_json": kwargs["output"],
        }
        return result

    result = ad_snapshot_projection.complete_projection_claim(
        Connection(cursor), claim=claim, manifest=manifest,
        load_exact=load_exact, persist_output=persist_output,
    )

    assert exact_calls == [("ad_context_base", "source-base-1", "b" * 64)]
    assert persisted == [{
        "manifest_id": MANIFEST_ID,
        "projection_key": "ad.state",
        "projection_version": 1,
        "input_sha256": result["input_sha256"],
        "output": {"source": "base", "source_id": "source-base-1"},
    }]
    completion_sql = cursor.executed[-1][0].casefold()
    assert "update ad_snapshot_projection_receipts" in completion_sql
    assert "status='completed'" in completion_sql
    assert result["output_identity"] == f"{MANIFEST_ID}:ad.state:v1"


def test_manifest_cycle_claims_only_its_exact_manifest_without_reacquisition() -> None:
    cursor = Cursor()
    claim = {
        "manifest_id": MANIFEST_ID,
        "projection_key": "ad.state",
        "projection_version": 1,
        "lease_owner": "coordinator",
    }
    manifest = {
        "manifest_id": MANIFEST_ID,
        "manifest_sha256": "f" * 64,
        "members": {
            "ad_context_base": {
                "source_id": "source-base-1",
                "payload_sha256": "b" * 64,
            }
        },
    }
    claims: list[dict[str, object]] = []
    manifests: list[str] = []
    exact_calls: list[tuple[str, str, str]] = []

    def load_manifest(_conn, manifest_id):
        manifests.append(manifest_id)
        return manifest

    def claim_receipts(_conn, **kwargs):
        claims.append(kwargs)
        return [claim]

    def ensure_receipts(_conn, *, manifest_id):
        assert manifest_id == MANIFEST_ID
        return _receipt_rows(
            completed=("ad.users.v2", "ad.computers.v6", "ad.gpo.v2")
        )

    def revalidate_completed(_conn, *, receipt):
        return {"status": "completed", "readback": "verified"}

    def load_exact(family, source_id, payload_sha256):
        exact_calls.append((family, source_id, payload_sha256))
        return {"source": "base", "source_id": source_id}

    def complete_claim(_conn, **kwargs):
        loaded = kwargs["load_exact"]("ad_context_base", "source-base-1", "b" * 64)
        assert loaded == {"source": "base", "source_id": "source-base-1"}
        return {
            "input_sha256": "c" * 64,
            "output_sha256": _canonical(loaded),
            "output_identity": f"{MANIFEST_ID}:ad.state:v1",
        }

    result = ad_snapshot_projection.run_exact_manifest_projection_cycle(
        Connection(cursor), manifest_id=MANIFEST_ID, worker_id="coordinator",
        load_manifest=load_manifest, load_exact=load_exact,
        ensure_receipts=ensure_receipts, revalidate_completed=revalidate_completed,
        claim_receipts=claim_receipts, complete_claim=complete_claim,
    )

    assert manifests == [MANIFEST_ID]
    assert claims == [{"worker_id": "coordinator", "manifest_id": MANIFEST_ID}]
    assert exact_calls == [("ad_context_base", "source-base-1", "b" * 64)]
    assert result["status"] == "completed"
    assert result["projection_results"]["ad.state"]["output_identity"] == f"{MANIFEST_ID}:ad.state:v1"


def _receipt_rows(*, completed: tuple[str, ...] = ()) -> list[dict[str, object]]:
    return [
        {
            "manifest_id": MANIFEST_ID,
            "projection_key": projection_key,
            "projection_version": version,
            "status": "completed" if projection_key in completed else "pending",
            "input_sha256": "a" * 64 if projection_key in completed else None,
            "output_sha256": "b" * 64 if projection_key in completed else None,
            "output_identity": f"{MANIFEST_ID}:{projection_key}:v{version}" if projection_key in completed else None,
        }
        for projection_key, version in PROJECTION_ALLOWLIST.items()
    ]


def test_cycle_ensures_four_receipts_revalidates_completed_before_same_manifest_claim() -> None:
    cursor = Cursor()
    manifest = {
        "manifest_id": MANIFEST_ID,
        "manifest_sha256": "f" * 64,
        "members": {
            "ad_context_base": {
                "source_id": "source-base-1",
                "payload_sha256": "b" * 64,
            }
        },
    }
    events: list[str] = []
    exact_calls: list[tuple[str, str, str]] = []
    state_claim = {
        "manifest_id": MANIFEST_ID,
        "projection_key": "ad.state",
        "projection_version": 1,
        "lease_owner": "coordinator",
    }

    def ensure_receipts(_conn, *, manifest_id):
        events.append(f"ensure:{manifest_id}")
        return _receipt_rows(completed=("ad.users.v2", "ad.computers.v6", "ad.gpo.v2"))

    def revalidate_completed(_conn, *, receipt):
        events.append(f"readback:{receipt['projection_key']}")
        return {"status": "completed", "readback": "verified"}

    def claim_receipts(_conn, **kwargs):
        events.append("claim")
        assert kwargs == {"worker_id": "coordinator", "manifest_id": MANIFEST_ID}
        return [state_claim]

    def complete_claim(_conn, **kwargs):
        events.append(f"complete:{kwargs['claim']['projection_key']}")
        return {
            "input_sha256": "c" * 64,
            "output_sha256": "d" * 64,
            "output_identity": f"{MANIFEST_ID}:ad.state:v1",
        }

    def load_exact(family, source_id, payload_sha256):
        exact_calls.append((family, source_id, payload_sha256))
        return {"source": "base", "source_id": source_id}

    result = ad_snapshot_projection.run_exact_manifest_projection_cycle(
        Connection(cursor),
        manifest_id=MANIFEST_ID,
        worker_id="coordinator",
        load_manifest=lambda _conn, _manifest_id: manifest,
        load_exact=load_exact,
        ensure_receipts=ensure_receipts,
        revalidate_completed=revalidate_completed,
        claim_receipts=claim_receipts,
        complete_claim=complete_claim,
    )

    assert events == [
        f"ensure:{MANIFEST_ID}",
        "readback:ad.users.v2",
        "readback:ad.computers.v6",
        "readback:ad.gpo.v2",
        "claim",
        "complete:ad.state",
    ]
    assert exact_calls == []
    assert set(result["projection_results"]) == set(PROJECTION_ALLOWLIST)
    assert result["projection_results"]["ad.users.v2"] == {
        "status": "completed", "readback": "verified"
    }
    assert result["projection_results"]["ad.state"]["readback"] == "inserted_and_verified"
    assert result["status"] == "completed"


def test_completed_receipt_missing_output_becomes_retryable_failed_without_backfill() -> None:
    class MissingOutputCursor(Cursor):
        def fetchone(self):
            return None

    receipt = _receipt_rows(completed=("ad.state",))[-1]
    cursor = MissingOutputCursor()

    result = ad_snapshot_projection.revalidate_completed_projection_receipt(
        Connection(cursor), receipt=receipt
    )

    assert result["status"] == "failed"
    assert result["retryable"] is True
    assert "missing" in result["error"].casefold()
    sql = "\n".join(statement.casefold() for statement, _ in cursor.executed)
    assert "from ad_snapshot_projection_outputs" in sql
    assert "status='failed'" in sql
    assert "delete from" not in sql and "latest" not in sql


def test_present_mismatched_completed_output_fails_closed_without_receipt_rewrite() -> None:
    cursor = OutputCursor()
    receipt = _receipt_rows(completed=("ad.state",))[-1]
    cursor.output = {
        "manifest_id": MANIFEST_ID,
        "projection_key": "ad.state",
        "projection_version": 1,
        "input_sha256": "0" * 64,
        "output_sha256": "b" * 64,
        "output_identity": f"{MANIFEST_ID}:ad.state:v1",
        "payload_json": {"exact": True},
    }

    with pytest.raises(ProjectionConflictError, match="readback mismatch"):
        ad_snapshot_projection.revalidate_completed_projection_receipt(
            Connection(cursor), receipt=receipt
        )

    assert len(cursor.executed) == 1
    assert "from ad_snapshot_projection_outputs" in cursor.executed[0][0].casefold()


def test_direct_receipt_completion_without_durable_output_readback_is_rejected() -> None:
    claim = {
        "manifest_id": MANIFEST_ID,
        "projection_key": "ad.state",
        "projection_version": 1,
        "lease_owner": "coordinator",
    }

    with pytest.raises(ProjectionConflictError, match="missing"):
        record_projection_result(
            Connection(Cursor()),
            claim=claim,
            result={
                "input_sha256": "a" * 64,
                "output_sha256": "b" * 64,
                "output_identity": f"{MANIFEST_ID}:ad.state:v1",
            },
        )


def test_output_conflict_raises_and_does_not_rewrite_the_claimed_receipt() -> None:
    claim = {
        "manifest_id": MANIFEST_ID,
        "projection_key": "ad.state",
        "projection_version": 1,
        "lease_owner": "coordinator",
    }
    manifest = {
        "manifest_id": MANIFEST_ID,
        "manifest_sha256": "f" * 64,
        "members": {
            "ad_context_base": {
                "source_id": "source-base-1",
                "payload_sha256": "b" * 64,
            }
        },
    }
    cursor = Cursor()

    with pytest.raises(ProjectionConflictError, match="identity mismatch"):
        ad_snapshot_projection.complete_projection_claim(
            Connection(cursor),
            claim=claim,
            manifest=manifest,
            load_exact=lambda *_args: {"source": "exact"},
            persist_output=lambda *_args, **_kwargs: {
                "input_sha256": "a" * 64,
                "output_sha256": "b" * 64,
                "output_identity": "not-manifest-bound",
            },
        )

    assert not cursor.executed


def test_migration_129_and_schema_block_have_additive_immutable_output_parity() -> None:
    forward = (ROOT / "config/postgres_migrations/129_ad_snapshot_projection_retention.sql").read_text(encoding="utf-8").casefold()
    rollback = (ROOT / "config/postgres_migrations/129_ad_snapshot_projection_retention.rollback.sql").read_text(encoding="utf-8").casefold()
    schema = (ROOT / "config/postgres_schema.sql").read_text(encoding="utf-8").casefold()

    assert "create table if not exists public.ad_snapshot_projection_outputs" in forward
    assert "references public.ad_snapshot_manifests(manifest_id) on delete restrict" in forward
    assert "create table if not exists ad_snapshot_projection_outputs" in schema
    assert "references ad_snapshot_manifests(manifest_id) on delete restrict" in schema
    for text in (forward, schema):
        assert "primary key(manifest_id, projection_key, projection_version)" in text
        assert "unique(output_identity)" in text
        assert "octet_length(input_sha256) = 32" in text
        assert "octet_length(output_sha256) = 32" in text
        assert "output_identity = manifest_id::text || ':' || projection_key || ':v' || projection_version::text" in text
        assert "ad_snapshot_projection_outputs_allowlist_check" in text
        assert "trg_ad_snapshot_projection_outputs_immutable" in text
        assert "ad_snapshot_projection_receipts_completed_output_check" in text
        assert "not valid" in text
        assert ("grant select, insert on table public.ad_snapshot_projection_outputs to adlog_user" in forward if text is forward else "grant select, insert on table ad_snapshot_projection_outputs to adlog_user" in schema)

    for predecessor in (
        "version = 121",
        "name = 'ad_snapshot_manifest_foundation'",
        "version = 122",
        "name = 'ad_snapshot_runtime_grants'",
        "version = 128",
        "name = 'ad_snapshot_v2_schedule'",
    ):
        assert predecessor in forward
    assert "pg_advisory_xact_lock" in forward
    assert "values (129, 'ad_snapshot_projection_retention')" in forward
    assert "adlog_context_worker" in forward
    assert "grant update on table ad_snapshot_projection_outputs" not in forward
    assert "grant delete on table ad_snapshot_projection_outputs" not in forward

    first_mutation = min(
        index for index in (rollback.index("revoke "), rollback.index("drop ")) if index >= 0
    )
    assert rollback.index("raise exception") < first_mutation
    assert "exists(select1frompublic.ad_snapshot_projection_outputs)" in rollback.replace(" ", "")
    assert "status = 'completed'" in rollback
    assert "delete from ad_snapshot_projection_outputs" not in rollback
    assert "truncate ad_snapshot_projection_outputs" not in rollback
    assert "delete from public.schema_migrations" in rollback
    assert "where version = 129" in rollback


def test_dormant_projection_shim_requires_exact_manifest_and_delegates_common_cycle() -> None:
    source = (ROOT / "scripts/runtime/ad_snapshot_projection_worker.py").read_text(encoding="utf-8").casefold()

    assert "run_exact_manifest_projection_cycle" in source
    assert "--manifest-id" in source and "required=true" in source
    assert "claim_projection_receipts" not in source
    assert "record_projection_result" not in source
    assert "latest" not in source


@pytest.mark.parametrize("gpo_enabled", [False, True])
def test_coordinator_attaches_exact_projection_and_ring_expiration_without_source_reacquisition(monkeypatch, gpo_enabled) -> None:
    from datetime import datetime, timezone
    from scripts.runtime import ad_snapshot_manifest_coordinator_worker as coordinator
    from server.sli.sources import ad_gpo_jobs

    monkeypatch.setattr(ad_gpo_jobs, "gpo_snapshot_enabled", lambda: gpo_enabled)

    monkeypatch.setenv("ADLOG_AD_CONTEXT_DOMAIN", "example.test")

    class DomainCursor:
        def __init__(self) -> None:
            self.executed: list[str] = []

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, sql, _params=None):
            self.executed.append(str(sql))

        def fetchall(self):
            return [{"id": 7, "domain_sid": "S-1-5-21-1", "fqdn": "example.test"}]

    class DomainConnection:
        def __init__(self) -> None:
            self.value = DomainCursor()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def cursor(self):
            return self.value

        def commit(self):
            pass

    connections: list[DomainConnection] = []
    projection_calls: list[tuple[object, dict[str, object]]] = []
    history_calls: list[tuple[object, int, str]] = []

    projection_results = {
        key: {"status": "completed", "readback": "verified"}
        for key in PROJECTION_ALLOWLIST
    }

    def connect():
        connection = DomainConnection()
        connections.append(connection)
        return connection

    monkeypatch.setattr(coordinator, "connect", connect)
    monkeypatch.setattr(coordinator.ad_history.ch, "configured_read_port", lambda: 8123)
    monkeypatch.setattr(coordinator.ad_history, "ensure_schema", lambda *_: None)
    monkeypatch.setattr(coordinator.ad_history, "publish_manifest", lambda *args:
                        history_calls.append(args) or {"status": "confirmed", "records_published": 0})
    monkeypatch.setattr(
        coordinator,
        "run_one_shot",
        lambda **_kwargs: {
            "status": "replayed_existing",
            "manifest_id": MANIFEST_ID,
            "coverage_state": "partial",
            "source_contacted": False,
            "database_modified": False,
            "composition": {"version": 1, "parts": ["base_ad", "gpo"] if gpo_enabled else ["base_ad"]},
        },
    )
    monkeypatch.setattr(
        coordinator,
        "run_exact_manifest_projection_cycle",
        lambda connection, **kwargs: projection_calls.append((connection, kwargs)) or {
            "status": "completed",
            "manifest_id": MANIFEST_ID,
            "projection_results": projection_results,
        },
        raising=False,
    )

    result = coordinator._default_cycle(
        datetime(2026, 9, 1, 11, tzinfo=timezone.utc),
        domain_dns="example.test",
        scheduled_slot=coordinator.ScheduledSlot(
            schedule_timezone="Asia/Novosibirsk",
            scheduled_local_at="2026-09-01T18:00:00",
            slot_start_utc="2026-09-01T11:00:00Z",
        ),
        worker_id="coordinator-test",
    )

    assert result["status"] == "replayed_existing"
    assert result["coverage_state"] == "partial"
    assert result["projection_results"] == projection_results
    assert result["retention_execution"] == ({
        "status": "executed",
        "procedure": "public.expire_ad_snapshot_confirmed_ring_v165",
        "manifest_id": MANIFEST_ID,
    } if gpo_enabled else {"status": "skipped", "reason": "retention_requires_full_composition"})
    assert len(projection_calls) == 1
    assert history_calls == ([(connections[-1], 8123, MANIFEST_ID)] if gpo_enabled else [])
    assert ("call public.expire_ad_snapshot_confirmed_ring_v165(%s::uuid)" in
            "\n".join(connections[-1].value.executed).casefold()) is gpo_enabled
    assert projection_calls[0][1] == {
        "manifest_id": MANIFEST_ID,
        "worker_id": "coordinator-test",
        **({} if gpo_enabled else {"projection_keys": ("ad.state", "ad.users.v2", "ad.computers.v6")}),
    }
