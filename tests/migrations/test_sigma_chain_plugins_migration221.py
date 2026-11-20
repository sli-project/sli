"""Dormant package registration and narrowly locked worker admission; no DB."""
import json
from pathlib import Path
import re

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from server.sli.core.job_queue import digest

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/221_sigma_chain_plugins.sql"
SQL = PATH.read_text("utf-8")


def test_forward_migration_has_exact_predecessor_and_dormant_manifest_pin():
    pairs = [(m.version, m.name) for m in forward_migration_inventory(PATH.parent)]
    assert pairs[pairs.index((221, "sigma_chain_plugins")) - 1] == (220, "detection_match_risk")
    assert len(pairs) == len({number for number, _ in pairs})
    assert list(PATH.parent.glob("221_*.sql")) == [PATH]
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in SQL
    assert "version=220 and name='detection_match_risk'" in SQL
    assert "where version>=221" in SQL
    assert SQL.strip().startswith("-- Sigma stage 17:") and SQL.strip().endswith("commit;")
    assert "values(221,'sigma_chain_plugins')" in SQL
    manifest = json.loads((ROOT / "config/plugin_packages/v3/sli.sigma.json").read_text("utf-8"))
    assert f"'sli.sigma','sli.sigma.package.v3','{digest(manifest)}'" in SQL
    assert "'1.0.0','registered','disabled','unknown','stopped','drained',1,1" in SQL
    assert SQL.count("on conflict(plugin_id) do nothing;") == 2


def test_reader_locks_only_chain_providers_until_transaction_finishes():
    reader = SQL.split("create function public.read_sigma_chain_plugin_states_v1()", 1)[1].split("$$;", 1)[0]
    assert "security definer set search_path=pg_catalog,pg_temp" in reader
    assert "from public.plugin_installations_v1 i" in reader
    assert "i.package_lifecycle='registered'" in reader
    assert "i.desired_activation='enabled_manual'" in reader
    assert "coalesce(s.configured,false)" in reader
    assert "where i.plugin_id in ('sli.ad','sli.sigma')" in reader
    assert "order by i.plugin_id\n    for share of i;" in reader
    assert "revoke all on function public.read_sigma_chain_plugin_states_v1() from public;" in SQL
    assert "grant execute on function public.read_sigma_chain_plugin_states_v1() to adlog_semantic_worker;" in SQL
    assert not re.search(r"grant\s+(?:select|insert|update|delete|truncate|all)\b", SQL, re.I)


def test_install_never_mutates_existing_states_policies_or_history():
    assert not re.search(r"\b(?:delete|update|truncate|drop)\b", SQL, re.I)
    assert "semantic_detection_matches" not in SQL and "semantic_risk_policies" not in SQL
    assert "findings" not in SQL and "evidence_refs" not in SQL
    assert "to adlog_user" not in SQL
