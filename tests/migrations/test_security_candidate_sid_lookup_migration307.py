"""Exact SID lookup keeps alias reads behind the existing owner identity."""
import os
import re
from pathlib import Path

import pytest

from tests.postgres_integration_guard import assert_disposable_database

ROOT = Path(__file__).resolve().parents[2]
SIGNATURE = "public.security_candidate_sid_matches_v307(bigint,integer,text)"
SID = "S-1-5-21-100000001-200000002-300000003-55"
pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]


def test_owner_definer_preserves_closed_aliases_and_round_trips_306():
    psycopg = pytest.importorskip("psycopg")
    dsn = os.environ.get("ADLOG_TEST_PG_DSN", "")
    if not dsn:
        pytest.skip("disposable PostgreSQL not configured")
    forward = (ROOT / "config/postgres_migrations/307_security_candidate_sid_lookup.sql").read_text("utf-8")
    rollback = (ROOT / "config/postgres_migrations/307_security_candidate_sid_lookup.rollback.sql").read_text("utf-8")
    baseline = (ROOT / "config/postgres_baseline/baseline.sql").read_text("utf-8")
    active = re.search(r"CREATE FUNCTION public\.entity_v2_is_active\(.*?\$\$;", baseline, re.S)
    assert active is not None
    with psycopg.connect(dsn, autocommit=True) as conn:
        assert_disposable_database(conn)
        conn.execute("""grant usage,create on schema public to adlog_storage_owner;
            grant usage on schema public to adlog_user;
            set role adlog_storage_owner;
            create table public.schema_migrations(version integer primary key,name text);
            insert into public.schema_migrations values(306,'password_policy_reconciliation');
            create table public.entities_v2(id integer primary key,domain_id bigint);
            create table public.ad_context_entity_aliases(entity_id integer,domain_id bigint,
                alias_type text,normalized_value text);
            create table public.entity_identity_merges_v2(source_entity_id bigint);
            insert into public.entities_v2 values(55,1),(56,1);
            insert into public.entity_identity_merges_v2 values(56);
            """)
        conn.execute(active.group())
        conn.execute("reset role")
        conn.execute("insert into public.ad_context_entity_aliases values(55,1,'object_sid',lower(%s)),"
                     "(56,1,'object_sid',lower(%s))", (SID, SID))
        roles = conn.execute("select oid,rolname from pg_roles order by oid").fetchall()
        alias_acl = conn.execute("select relowner,relacl from pg_class where oid='public.ad_context_entity_aliases'::regclass").fetchone()
        for _ in range(2):
            conn.execute(forward)
            assert conn.execute("""select pg_get_userbyid(proowner),prosecdef,proisstrict,provolatile,proconfig
                from pg_proc where oid=to_regprocedure(%s)""", (SIGNATURE,)).fetchone() == (
                    "adlog_storage_owner", True, True, "s", ["search_path=pg_catalog, pg_temp"])
            assert conn.execute("""select pg_get_userbyid(a.grantee),a.privilege_type,a.is_grantable
                from pg_proc p cross join lateral aclexplode(p.proacl) a
                where p.oid=to_regprocedure(%s) and a.grantee<>p.proowner""", (SIGNATURE,)).fetchall() == [
                    ("adlog_user", "EXECUTE", False)]
            conn.execute("set role adlog_user")
            try:
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    conn.execute("select normalized_value from public.ad_context_entity_aliases")
                for domain, entity, sid, expected in (
                    (1, 55, SID, True), (1, 55, " " + SID.lower() + " ", True),
                    (2, 55, SID, False), (1, 57, SID, False), (1, 56, SID, False),
                    (1, 55, SID + "0", False), (1, 55, None, None),
                ):
                    assert conn.execute("select public.security_candidate_sid_matches_v307(%s,%s,%s)",
                                        (domain, entity, sid)).fetchone() == (expected,)
            finally:
                conn.execute("reset role")
            conn.execute(rollback)
            assert conn.execute("select to_regprocedure(%s)", (SIGNATURE,)).fetchone() == (None,)
            assert conn.execute("select version,name from public.schema_migrations").fetchall() == [
                (306, "password_policy_reconciliation")]
            assert conn.execute("select oid,rolname from pg_roles order by oid").fetchall() == roles
            assert conn.execute("select relowner,relacl from pg_class where oid='public.ad_context_entity_aliases'::regclass").fetchone() == alias_acl
