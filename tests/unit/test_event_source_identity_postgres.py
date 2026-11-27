"""Migration 284 and real SQL replay in disposable PostgreSQL only."""
import os
from pathlib import Path

import pytest


SQL = (Path(__file__).resolve().parents[2] / "config/postgres_migrations/284_event_source_identity.sql").read_text(encoding="utf-8")


def test_additive_migration_preserves_hashes_and_has_exact_predecessor():
    assert "version=283 and name='file_audit_snapshot_hash'" in SQL
    assert "version>=284" in SQL
    assert "update events_v2_core" not in SQL and "update storage_v2_event_identity_allocations" not in SQL
    assert "grant update(representation,representation_sha256)" in SQL
    assert "i.imported_at is not null" in SQL
    assert "grant execute on function public.recheck_agent_quarantine_v284(uuid,text) to adlog_user" in SQL


def test_semantic_reader_exposes_only_exact_imported_source_and_preferred_representation():
    reader = SQL.split("create or replace function public.read_agent_semantic_source_v190", 1)[1].split("$$;", 1)[0]
    assert "security definer" in reader and "set search_path=pg_catalog,public" in reader
    assert "'preferred',to_jsonb(preferred)" in reader
    assert "preferred.event_id=core.id" in reader
    assert "core.id=p_event_id and p_event_id>0" in reader
    assert "inbox.imported_at is not null" in reader
    assert "receipt.receipt->>'status'='committed'" in reader
    assert "inbox.envelope=receipt.envelope" in reader
    assert "count(*)=1" in reader
    assert "core.event_id in (4608,4624,4625" in reader
    assert "interval '1 microsecond'" in reader
    assert "grant select on public.event_source_representations_v2 to adlog_semantic_worker" not in SQL
