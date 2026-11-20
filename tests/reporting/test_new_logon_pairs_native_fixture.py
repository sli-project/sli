"""Exercise T002 seeding against the migrated, disposable PostgreSQL baseline."""
from datetime import datetime, timezone
import os
from uuid import uuid4

import pytest

from tests.reporting.new_logon_pairs_native_fixture import seed_native_context, synthetic_snapshot


pytestmark = pytest.mark.postgres_integration
CONTEXT_TABLES = (
    "servers", "ad_context_runs", "entities_v2", "users_report_v2_snapshots",
    "computers_v6_source_snapshots",
)


@pytest.fixture
def connection():
    dsn = os.environ.get("ADLOG_TEST_PG_DSN", "").strip()
    if not dsn:
        pytest.skip("Disposable PostgreSQL DSN required")
    import psycopg
    from psycopg.rows import dict_row
    from tests.postgres_integration_guard import assert_disposable_database

    with psycopg.connect(dsn, row_factory=dict_row) as conn:
        assert_disposable_database(conn)
        yield conn


def test_native_fixture_uses_empty_migrated_baseline_domain(connection):
    before = connection.execute("select id,forest_id,fqdn from domains").fetchall()
    assert len(before) == 1 and before[0]["fqdn"] == "example.test"
    fixture = seed_native_context(connection, observed_at=datetime.now(timezone.utc), population=2)
    assert fixture["domain_id"] == before[0]["id"]
    assert connection.execute("select id,forest_id,fqdn from domains").fetchall() == before
    assert len(fixture["server_ids"]) == len(fixture["computer_guids"]) == 2
    for table, expected in zip(CONTEXT_TABLES, (2, 1, 2, 1, 1), strict=True):
        assert connection.execute(
            f"select count(*) as count from {table} where domain_id=%s", (fixture["domain_id"],)
        ).fetchone()["count"] == expected


@pytest.mark.parametrize("table", CONTEXT_TABLES)
def test_native_fixture_refuses_populated_context_without_changing_rows(connection, table):
    domain = connection.execute("select id from domains where fqdn='example.test'").fetchone()["id"]
    now = datetime.now(timezone.utc)
    if table == "servers":
        connection.execute(
            "insert into servers(domain_id,hostname,fqdn,role) values (%s,'EXISTING','existing.example.test','domain_controller')",
            (domain,),
        )
    elif table == "ad_context_runs":
        connection.execute(
            """insert into ad_context_runs(run_id,source_pack_id,source_pack_version,domain_id,
               mode,observed_at_utc,bundle_sha256,status,completed_at)
               values (%s,'existing-synthetic','1',%s,'full',%s,%s,'completed',%s)""",
            (uuid4(), domain, now, b"1" * 32, now),
        )
    elif table == "entities_v2":
        connection.execute("insert into storage_v2_entity_type(value) values ('ad_computer') on conflict do nothing")
        connection.execute(
            """insert into entities_v2(entity_type_id,natural_key,display_name,domain_id,
               first_seen_utc,last_seen_utc,source_core_sha256)
               select id,'existing-synthetic','Existing synthetic',%s,%s,%s,%s
               from storage_v2_entity_type where value='ad_computer'""",
            (domain, now, now, b"1" * 32),
        )
    elif table == "users_report_v2_snapshots":
        connection.execute(
            """insert into users_report_v2_snapshots(domain_id,contract_id,schema_version,
               scope_json,scope_sha256,bucket_start_utc,captured_at_utc,source_observed_at_utc,
               source_state,user_count,payload_json,payload_sha256)
               values (%s,'sli.users-report.v2',1,'{}'::jsonb,%s,%s,%s,%s,'complete',0,
               '{"users":[]}'::jsonb,%s)""",
            (domain, b"1" * 32, now, now, now, b"1" * 32),
        )
    else:
        from server.sli.plugins.ad.snapshots.computers_persistence import persist_computers_v6_source_snapshot

        persist_computers_v6_source_snapshot(
            connection, snapshot=synthetic_snapshot(now, 2), captured_at=now,
            capture_options={"server": "dc-1.example.test"}, collector_exit_code=0,
        )
    connection.commit()
    # Preserve both the existing payload and every other context table, including
    # the installation's forest/domain rows. No cleanup or overwrite is allowed.
    tables = (*CONTEXT_TABLES, "domains", "forests")
    before = {name: connection.execute(f"select row_to_json(t) as row from {name} t").fetchall() for name in tables}
    with pytest.raises(AssertionError, match="native fixture requires"):
        seed_native_context(connection, observed_at=now, population=2)
    after = {name: connection.execute(f"select row_to_json(t) as row from {name} t").fetchall() for name in tables}
    assert after == before
