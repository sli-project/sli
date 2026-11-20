#!/usr/bin/env python3
"""Historical card indexes and post-rewrite visibility maintenance stay gated."""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from tests.postgres_integration_guard import assert_disposable_database

PATH = Path(__file__).resolve().parents[2] / "config/postgres_migrations/248_entity_context_history_reads.sql"


def test_history_migration_is_owner_gated_retryable_and_registered_after_maintenance(tmp_path):
    sql = PATH.read_text("utf-8")
    # Validate this file's registration independently of unrelated migrations;
    # test_migration_numbers_unique validates the complete checkout separately.
    (tmp_path / PATH.name).write_text(sql, encoding="utf-8")
    inventory = [(row.version, row.name) for row in forward_migration_inventory(tmp_path)]
    assert (248, "entity_context_history_reads") in inventory
    project_inventory = [(row.version, row.name) for row in forward_migration_inventory(PATH.parent)]
    assert project_inventory[project_inventory.index((248, "entity_context_history_reads")) - 1] == (247, "decoy_delivery_context")
    for fragment in (
        "pg_advisory_lock(hashtext('sli_entity_context_history_reads_v248'))",
        "pg_has_role(session_user,'adlog_storage_owner','MEMBER')",
        "version=247 and name='decoy_delivery_context'",
        "version=237 and name='entity_context_health'",
        "where version>=248",
        "set role adlog_storage_owner;",
        "reset role;",
        "pg_advisory_unlock(hashtext('sli_entity_context_history_reads_v248'))",
    ):
        assert fragment in sql
    statements = "\n".join(line for line in sql.splitlines() if not line.startswith("--"))
    assert "begin;" not in statements.lower() and "commit;" not in statements.lower()
    vacuum = "vacuum (analyze) public.sli_agent_packet_inbox;"
    assert sql.index("analyze public.ad_context_evidence;") < sql.index("set role adlog_storage_owner;") < sql.index(vacuum)
    assert sql.index(vacuum) < sql.index("values(248,'entity_context_history_reads')")
    for forbidden in ("delete ", "update ", "grant ", "alter table", "vacuum full"):
        assert forbidden not in statements.lower()


def test_history_indexes_cover_closed_versions_and_exact_participants():
    sql = " ".join(PATH.read_text("utf-8").split())
    for table, participant in (
        ("ad_context_entity_versions", "entity_id"),
        ("ad_context_relation_versions", "source_entity_id"),
        ("ad_context_relation_versions", "target_entity_id"),
    ):
        assert f"on public.{table}({participant},(valid_to_utc is null) desc,last_observed_at_utc desc);" in sql
        assert f"analyze public.{table};" in sql
    assert sql.count("create index if not exists") == 3
    assert "where valid_to_utc is null" not in sql
    assert "analyze public.ad_context_evidence;" in sql


@pytest.mark.postgres_integration
@pytest.mark.parametrize("partial_retry", [False, True])
def test_history_migration_preserves_mixed_table_ownership(partial_retry):
    dsn = os.environ.get("ADLOG_TEST_PG_DSN", "").strip()
    if not dsn:
        pytest.skip("ADLOG_TEST_PG_DSN is required for disposable PostgreSQL tests")
    psycopg = pytest.importorskip("psycopg")
    indexes = (
        "idx_ad_context_entity_history",
        "idx_ad_context_relation_source_history",
        "idx_ad_context_relation_target_history",
    )
    expected_owners = [
        ("ad_context_entity_versions", "adlog_user"),
        ("ad_context_evidence", "adlog_user"),
        ("ad_context_relation_versions", "adlog_user"),
        ("sli_agent_packet_inbox", "adlog_storage_owner"),
    ]
    owners_query = """select tablename, tableowner from pg_tables
        where schemaname='public' and tablename in (
            'ad_context_entity_versions', 'ad_context_evidence',
            'ad_context_relation_versions', 'sli_agent_packet_inbox')
        order by tablename"""
    with psycopg.connect(dsn, autocommit=True) as connection:
        assert_disposable_database(connection)
        assert connection.execute(owners_query).fetchall() == expected_owners
        assert connection.execute(
            "select has_schema_privilege('adlog_user','public','CREATE')"
        ).fetchone() == (False,)
        # Reapply from the exact predecessor in this disposable per-test clone.
        # Later migration markers must not block the ownership/retry assertions.
        connection.execute("delete from public.schema_migrations where version>=248")
        for index in indexes:
            connection.execute(psycopg.sql.SQL("drop index if exists public.{}").format(psycopg.sql.Identifier(index)))
        if partial_retry:
            connection.execute("""create index idx_ad_context_entity_history
                on public.ad_context_entity_versions
                (entity_id,(valid_to_utc is null) desc,last_observed_at_utc desc)""")

        result = subprocess.run(
            [shutil.which("psql"), "--dbname", dsn, "--no-psqlrc",
             "--set", "ON_ERROR_STOP=1", "--file", str(PATH)],
            capture_output=True, text=True, check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "WARNING:" not in result.stderr
        assert connection.execute(owners_query).fetchall() == expected_owners
        assert connection.execute(
            "select version, name from public.schema_migrations where version=248"
        ).fetchone() == (248, "entity_context_history_reads")
        assert connection.execute(
            "select indexname from pg_indexes where schemaname='public' and indexname=any(%s) order by indexname",
            (list(indexes),),
        ).fetchall() == [(index,) for index in indexes]
        assert connection.execute(
            "select pg_has_role('adlog_user','adlog_storage_owner','MEMBER')"
        ).fetchone() == (False,)
        assert connection.execute(
            "select has_schema_privilege('adlog_user','public','CREATE')"
        ).fetchone() == (False,)
