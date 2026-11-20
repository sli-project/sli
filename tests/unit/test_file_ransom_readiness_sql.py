"""Structural migration guards; PG behavior is tested separately on disposable fixtures."""
from pathlib import Path

SQL = (Path(__file__).resolve().parents[2] / 'config/postgres_migrations/278_file_ransom_policy_readiness.sql').read_text()


def test_dependency_guard_precedes_function_replacement():
    guard = SQL.split('create or replace function', 1)[0]
    assert "version=277 and name='domain_archive_selection'" in guard
    assert "raise exception 'migration 278 prerequisites failed'" in guard


def test_retained_json_never_enters_integer_cast_in_global_discovery():
    readiness = SQL.split("jsonb_build_object('ransom_policy'", 1)[1].split("then 'ready'", 1)[0]
    assert "(policy.policy->>'mass_operation_files')::integer" not in readiness
    assert "(policy.policy->>'mass_operation_seconds')::integer" not in readiness
    assert 'policy.revision::text=' in readiness
    assert "'^[1-9][0-9]{0,6}$'" in readiness
