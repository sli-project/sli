from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest



ROOT = Path(__file__).resolve().parents[2]
MANIFEST_ID = "00000000-0000-4000-8000-000000000501"


def _canonical(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


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


def _resolver(member):
    from tests.migrations.test_ad_snapshot_manifest import _resolver as base
    return base(member)


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
