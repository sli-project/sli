"""Dormant package registration and narrowly locked worker admission; no DB."""
import json
from pathlib import Path
import re

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/221_sigma_chain_plugins.sql"
SQL = PATH.read_text("utf-8")


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
