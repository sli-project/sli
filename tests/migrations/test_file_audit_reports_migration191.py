"""Real read functions on an isolated PostgreSQL database in sli-dev pg-test."""
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from tests.postgres_integration_guard import assert_disposable_database

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/191_file_audit_reports.sql"


def test_reports_migration_follows_predecessor_and_versions_are_unique():
    inventory = forward_migration_inventory(PATH.parent)
    pairs = [(item.version, item.name) for item in inventory]
    position = pairs.index((191, "file_audit_reports"))
    assert position > 0
    assert pairs[position - 1] == (190, "agent_semantic_source")
    assert max(version for version, _ in pairs[:position]) + 1 == 191
    assert len(pairs) == len({version for version, _ in pairs})
    assert inventory[position].path == PATH
    assert list(PATH.parent.glob("191_*.sql")) == [PATH]


def test_read_functions_have_pinned_privileges_and_no_audit_mutation():
    sql = PATH.read_text("utf-8")
    manifest = json.loads((ROOT / "config/plugin_packages/v3/sli.file-audit.json").read_text("utf-8"))
    entries = [entry for entry in manifest["data"]["migrations"] if entry["version"] == 191]
    assert entries == [{"version": 191, "name": "file_audit_reports",
        "core_prerequisites": [190], "path": PATH.relative_to(ROOT).as_posix(),
        "sha256": hashlib.sha256(PATH.read_bytes().replace(b"\r\n", b"\n")).hexdigest()}]
    assert "version=190 and name='agent_semantic_source'" in sql and "where version>=191" in sql
    assert "values(191,'file_audit_reports')" in sql
    assert "pg_advisory_xact_lock(hashtext('sli_file_audit_reports_v191'))" in sql
    assert sql.count("security definer set search_path=pg_catalog,pg_temp") == 2
    assert sql.count("from public;") == 2
    assert "grant execute on function" in sql
    assert not re.search(r"grant (select|insert|update|delete).*to adlog_user", sql, re.IGNORECASE)
    assert "delete from" not in sql.lower() and "grant adlog_file_audit" not in sql


def test_report_publication_uses_migration_session_before_storage_ledger_role():
    """The storage owner cannot update the runtime-owned report registry."""
    sql = PATH.read_text("utf-8")
    publication = sql.split("reset role;", 1)[1]
    datasets, registry = publication.split("update public.report_registry_v4", 1)
    assert "update public.report_datasets_v4" in datasets
    assert "set local role" not in datasets
    registry_update, ledger = registry.split("set local role adlog_storage_owner;", 1)
    assert "status='published'" in registry_update
    assert "insert into public.schema_migrations" in ledger
