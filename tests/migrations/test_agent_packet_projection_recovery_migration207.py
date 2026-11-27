"""Additive recovery contracts and disposable PostgreSQL migration readback."""
import os
from pathlib import Path

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/207_agent_packet_projection_recovery.sql"
SQL = PATH.read_text(encoding="utf-8")


def test_exact_predecessor_owner_and_non_destructive_quarantine_contract():
    pairs = [(item.version, item.name) for item in forward_migration_inventory(PATH.parent)]
    assert pairs[pairs.index((207, "agent_packet_projection_recovery")) - 1] == (
        206, "file_audit_catalog_revision")
    assert len(pairs) == len({version for version, _ in pairs})
    assert list(PATH.parent.glob("207_*.sql")) == [PATH]
    assert "version=206 and name='file_audit_catalog_revision'" in SQL
    assert "where version>=207" in SQL
    assert "values(207,'agent_packet_projection_recovery')" in SQL
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in SQL
    assert "set local role adlog_storage_owner" in SQL
    assert "packet_id uuid primary key references public.sli_agent_packet_inbox(packet_id)" in SQL
    assert "source_event_allocation_hash_mismatch" in SQL and "published_source_event_hash_mismatch" in SQL
    assert "grant select,insert on public.sli_agent_packet_quarantine to adlog_user;" in SQL
    assert "grant select on public.sli_agent_packet_quarantine to adlog_nps_agent_import_worker;" in SQL
    assert not any(keyword in SQL.lower() for keyword in ("update ", "delete ", "drop "))
    assert SQL.strip().endswith("commit;")
