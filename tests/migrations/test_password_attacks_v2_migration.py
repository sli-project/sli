"""B1 native authority and transport budgets on synthetic disposable PostgreSQL."""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
from uuid import uuid4

import pytest

from tests.migrations.test_file_acl_semantic_migration265 import native_pg as native_pg
from tests.migrations.test_file_audit_acl_bridge_migration264 import acl_pg as acl_pg
from tests.migrations.test_file_audit_source_lookup_index_migration266 import observation_ddl

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/273_password_attacks_v2.sql"
AGENT = "00000000-0000-4000-8000-000000000098"
MIB = 1024 * 1024
pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]


def _function(migration, name):
    source = (PATH.parent / migration).read_text("utf-8-sig")
    return "create or replace function public." + name + "(" + source.split(
        "function public." + name + "(", 1)[1].split("$$;", 1)[0] + "$$;"


@pytest.fixture
def password_base_pg(native_pg):
    """Reuse actual264/265/266; current named190/219 authority, no fake verifier."""
    import psycopg

    with psycopg.connect(native_pg, autocommit=True) as conn:
        #Actual183/186 observation DDL and the merged266 index migration after
        #the actual264/265 fixture chain;266 body/index remain exercised.
        conn.execute("set role adlog_file_audit_owner")
        observation_ddl(conn)
        conn.execute("reset role")
        conn.execute((PATH.parent / "266_file_audit_source_lookup_index.sql").read_text("utf-8-sig"))
        # Unrelated269/270/271/272 synthetic predecessor markers; not full267-272 bootstrap.
        conn.execute("insert into schema_migrations values(269,'file_audit_canonical_aggregation')")
        conn.execute("insert into schema_migrations values(270,'account_decoy_source_prefilter')")
        conn.execute("insert into schema_migrations values(271,'account_watch_source_prefilter')")
        conn.execute("insert into schema_migrations values(272,'file_audit_assignment_policy')")
        conn.execute("set role adlog_storage_owner")
        conn.execute("""
            create table public.events_v2_core(id bigint primary key,event_id integer,log_source_id bigint,
                normalized_hash bytea,raw_log_file_id bigint,time_created_utc timestamptz,event_record_id bigint);
            create table public.raw_log_files(id bigint primary key,file_path text);
            create table public.sli_agent_packet_inbox(packet_id uuid primary key,envelope jsonb,packet jsonb,
                event_rows jsonb,imported_at timestamptz);
            create table public.sli_agent_receipts(packet_id uuid primary key,module_id text,envelope jsonb,receipt jsonb);
        """)
        #203 is the actual current definition of the190-named function.
        conn.execute(_function("203_agent_semantic_timestamp_precision.sql", "read_agent_semantic_source_v190"))
        conn.execute("""revoke all on function public.read_agent_semantic_source_v190(bigint) from public;
            grant execute on function public.read_agent_semantic_source_v190(bigint) to adlog_semantic_worker;
            reset role;
            alter table public.raw_log_files owner to adlog_user;
            grant select(id,file_path) on public.raw_log_files to adlog_storage_owner;
        """)
        #264's real resolver keeps219's exact core_event branch and ACL support.
        actual = conn.execute("select pg_get_functiondef('public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text)'::regprocedure)").fetchone()[0]
        assert "encode(e.normalized_hash,'hex')=p_sha256" in actual
        assert "receipt.receipt->>'status'='committed'" in actual
        assert "file_audit_snapshot_provenance_v264" in actual
        # Coverage uses actual pre-existing157/156/domain metadata, not a new issuer.
        # Restore EMPTY prerequisites omitted by reduced unrelated264/265 fixtures.
        schema = (PATH.parents[1] / "postgres_schema.sql").read_text("utf-8-sig")
        conn.execute(schema[schema.index("create table if not exists forests"):schema.index("create table if not exists sites")])
        conn.execute("alter table public.domains owner to adlog_user")  # actual baseline.sql owner
        conn.execute("grant references on public.domains to adlog_storage_owner")  # actual153
        conn.execute("grant select(id,fqdn,netbios_name) on public.domains to adlog_storage_owner")  # actual244
        conn.execute("set role adlog_storage_owner")
        packets = (PATH.parent / "157_agent_packets.sql").read_text("utf-8-sig")
        conn.execute(packets[packets.index("create table sli_agent_module_bindings"):packets.index("create table sli_agent_receipts")])
        ad_binding = (PATH.parent / "161_ad_dc_agent.sql").read_text("utf-8-sig")
        conn.execute(ad_binding[ad_binding.index("alter table sli_agent_module_bindings"):ad_binding.index("insert into")])
        agent = (PATH.parent / "156_agent_registry.sql").read_text("utf-8-sig")
        conn.execute(agent[agent.index("create table sli_agent_audit"):agent.index("create index sli_agent_audit_revocations")])
        conn.execute("alter table public.sli_agents add column policy_revision bigint not null default 1 check(policy_revision between 1 and 9007199254740991)")
        conn.execute("revoke all on public.sli_agent_module_bindings from public,adlog_user; grant select on public.sli_agent_module_bindings to adlog_user")
        conn.execute("grant select,insert on public.sli_agent_audit to adlog_user; grant usage,select on sequence public.sli_agent_audit_id_seq to adlog_user")
        conn.execute("reset role")
    return native_pg


@contextmanager
def _connection(source, *, worker=False):
    import psycopg
    from psycopg import sql
    from psycopg.rows import dict_row

    dsn, login = source
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as conn:
        if worker:
            #Test superuser changes session identity to a real LOGIN role.
            #SET ROLE alone must never authorize a source.
            conn.execute(sql.SQL("set session authorization {}").format(sql.Identifier(login)))
            conn.execute("set role adlog_semantic_worker")
        yield conn


def _xml(at, native_id=1, *, size=None, unicode=False):
    prefix = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
              '<System><EventID>4625</EventID>'
              f'<EventRecordID>{native_id}</EventRecordID><TimeCreated SystemTime="{at.isoformat()}"/>'
              '<Computer>fixture-collector</Computer></System><EventData>'
              '<Data Name="TargetUserName">fixture-account</Data><Data Name="TargetDomainName">fixture</Data>'
              '<Data Name="Status">0xc000006a</Data><Data Name="IpAddress">203.0.113.1</Data>'
              '<Data Name="Padding">')
    suffix = '</Data></EventData></Event>'
    if size is None:
        return prefix + suffix
    remaining = size - len((prefix + suffix).encode("utf-8"))
    assert remaining >= 0
    padding = "я" * (remaining // 2) + "x" * (remaining % 2) if unicode else "x" * remaining
    result = prefix + padding + suffix
    assert len(result.encode("utf-8")) == size
    return result


def _replace_xml(conn, native_id, xml):
    conn.execute("""update sli_agent_packet_inbox set event_rows=jsonb_set(event_rows,'{0,xml}',to_jsonb(%s::text))
        where packet_id=md5('password-v2-fixture-'||%s::text)::uuid""", (xml, native_id))


def _batch(rows):
    assert rows and rows[0]["record_kind"] == "metadata"
    assert sum(row["record_kind"] == "metadata" for row in rows) == 1
    metadata = rows[0]["metadata"]
    assert metadata["version"] == "sli.password.v2.window.1"
    assert all(rows[0][field] is None for field in
               ("source_event_id", "event_id", "occurred_at_utc", "sha256", "source_xml"))
    assert all(row["record_kind"] == "event" and row["metadata"] is None for row in rows[1:])
    return metadata, rows[1:]


def _native_row(admin, native_id=1):
    return admin.execute("""select id as source_event_id,event_id,time_created_utc as occurred_at_utc,
        encode(normalized_hash,'hex') as sha256,
        public.read_agent_semantic_source_v190(id)#>>'{event_row,xml}' as source_xml
        from public.events_v2_core where id=%s""", (native_id,)).fetchone()


@pytest.mark.parametrize("guard", ["missing", "wrong_name", "occupied", "owner"])
def test_migration_guard_leaves_no_partial_objects(password_base_pg, guard):
    import psycopg

    assert PATH.exists(), "B1 migration273 is missing"
    with psycopg.connect(password_base_pg, autocommit=True) as conn:
        if guard == "missing":
            conn.execute("delete from schema_migrations where version=272")
        elif guard == "wrong_name":
            conn.execute("update schema_migrations set name='wrong' where version=272")
        elif guard == "occupied":
            conn.execute("insert into schema_migrations values(273,'occupied')")
        else:
            conn.execute("set session authorization adlog_user")
        with pytest.raises(psycopg.errors.RaiseException, match="migration 273 prerequisites failed"):
            conn.execute(PATH.read_text("utf-8-sig"))
        conn.execute("rollback")
        conn.execute("reset session authorization")
        assert conn.execute("select to_regprocedure('public.read_default_password_window_v2(jsonb)')").fetchone()[0] is None
        assert conn.execute("select to_regprocedure('public.read_password_retained_proof_v2(jsonb,jsonb)')").fetchone()[0] is None
        assert not conn.execute("""select 1 from pg_indexes where tablename='events_v2_core'
            and indexdef like '%log_source_id, time_created_utc, id%' and indexdef like '%WHERE%'""").fetchall()


def test_migration_failure_after_ddl_rolls_back_functions_index_and_ledger(password_base_pg):
    import psycopg

    assert PATH.exists(), "B1 migration273 is missing"
    migration = PATH.read_text("utf-8-sig")
    marker = "insert into public.schema_migrations(version,name) values(273,'password_attacks_v2');"
    assert marker in migration
    with psycopg.connect(password_base_pg, autocommit=True) as conn:
        with pytest.raises(psycopg.errors.DivisionByZero):
            conn.execute(migration.replace(marker, "select 1/0;\n" + marker))
        conn.execute("rollback")
        assert conn.execute("select to_regprocedure('public.read_default_password_window_v2(jsonb)')").fetchone()[0] is None
        assert conn.execute("select to_regclass('public.idx_password_v2_source_time')").fetchone()[0] is None
        assert conn.execute("select count(*) from schema_migrations where version=273").fetchone()[0] == 0
