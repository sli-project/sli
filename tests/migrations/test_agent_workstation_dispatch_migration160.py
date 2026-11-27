"""Additive privilege contract and optional PostgreSQL identity-function exercise."""
import hashlib
import json
import os
from pathlib import Path
import re
from uuid import uuid4

import pytest

ROOT = Path(__file__).resolve().parents[2]
SQL = (ROOT / "config/postgres_migrations/160_agent_workstation_dispatch.sql").read_text("utf-8")


def test_exact_predecessor_and_disabled_bundled_package():
    assert "version=159 and name='workstation_security'" in SQL
    header, _ = SQL.split("set local role adlog_storage_owner;", 1)
    assert "or exists(select 1 from public.schema_migrations where version>=160)" in header
    assert "raise exception 'migration 160 requires exact migration 159 workstation_security'" in header
    assert "values(160,'agent_workstation_dispatch')" in SQL
    assert "'1.0.0','registered','disabled','unknown','stopped','drained',1,1" in SQL
    # Applied SQL attests the historical package, including its original reports.
    # A separate guard checks current overview additions against this snapshot.
    manifest = json.loads((ROOT / "tests/fixtures/workstations/package-before-overview.v3.json").read_text("utf-8"))
    manifest["data"]["migrations"] = [item for item in manifest["data"]["migrations"] if item["version"] < 160]
    original_bytes = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
    assert hashlib.sha256(original_bytes).hexdigest() in SQL


def test_runtime_has_only_assignment_update_and_narrow_identity_capability():
    runtime_grants = [s for s in re.findall(r"grant[^;]+;", SQL) if "to adlog_user" in s]
    assert runtime_grants == [
        "grant update(assigned_modules) on public.sli_agents to adlog_user;",
        "grant execute on function public.resolve_agent_workstation_v160(uuid,uuid) to adlog_user;",
    ]
    assert "security definer set search_path=pg_catalog,public" in SQL
    assert "revoke all on function public.resolve_agent_workstation_v160(uuid,uuid) from public" in SQL
    assert "and r.module_id='sli.workstations'" in SQL and "a.status='active'" in SQL
    assert "s.installed and s.enabled" in SQL
    assert "delete from" not in SQL.lower()
    assert "'module_assign'" in SQL
    assert "sli.agent.key" in SQL and "agent-registry" in SQL
    assert "count(distinct a.target_entity_id)=1" in SQL
