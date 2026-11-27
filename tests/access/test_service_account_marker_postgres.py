"""Synthetic fixtures only, in the CI-owned disposable PostgreSQL database."""
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

import pytest


pytestmark = pytest.mark.postgres_integration


@pytest.fixture
def pg():
    dsn = (os.environ.get("ADLOG_TEST_PG_DSN") or "").strip()
    if not dsn:
        pytest.skip("Disposable migrated PostgreSQL required")
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    with psycopg.connect(dsn, row_factory=dict_row) as conn:
        yield conn


def test_migration_recovers_only_proven_origins_and_survives_evidence_deletion(pg):
    # Reconstruct the pre-280 shape in this test's private migrated clone.
    pg.execute("alter table auth_users drop column if exists is_service")
    pg.execute("delete from schema_migrations where version=280")
    cases = {
        "live": True, "issued": True, "partial": True,
        "failed": False, "wrong-subject": False, "wrong-actor": False,
        "wrong-target": False, "prefix-only": False,
    }
    ids = {}
    for name in cases:
        ids[name] = pg.execute(
            "insert into auth_users(username,password_hash,role,is_active) values (%s,'synthetic','viewer',false) returning id",
            ("report-key-synthetic-" + name,),
        ).fetchone()["id"]
    pg.execute(
        "insert into auth_api_keys(key_prefix,key_hash,label,role,report_subject_id) values ('synthetic-live','synthetic-hash','synthetic','viewer',%s)",
        (ids["live"],),
    )
    for name in ("issued", "partial", "failed", "wrong-subject", "wrong-actor", "wrong-target"):
        pg.execute(
            """insert into access_audit_v4(actor_type,action,subject_type,subject_id,target_type,target_key,outcome)
               values (%s,%s,%s,%s,%s,'1',%s)""",
            ("session" if name == "wrong-actor" else "local_operator",
             "report_key_capabilities_created" if name == "partial" else "report_api_key_issued",
             "group" if name == "wrong-subject" else "user", ids[name],
             "ad_domain" if name in ("partial", "wrong-target") else "api_key",
             "error" if name == "failed" else "ok"),
        )
    before = pg.execute("select id,role,is_active,password_hash from auth_users order by id").fetchall()
    acl_before = pg.execute("select relname,relowner,relacl from pg_class where oid in ('auth_users'::regclass,'auth_api_keys'::regclass,'access_audit_v4'::regclass) order by relname").fetchall()
    pg.commit()
    pg.execute(Path("config/postgres_migrations/280_service_account_origin.sql").read_text())
    observed = {row["id"]: row["is_service"] for row in pg.execute("select id,is_service from auth_users")}
    assert {name: observed[id_] for name, id_ in ids.items()} == cases
    assert pg.execute("select id,role,is_active,password_hash from auth_users order by id").fetchall() == before
    assert pg.execute("select relname,relowner,relacl from pg_class where oid in ('auth_users'::regclass,'auth_api_keys'::regclass,'access_audit_v4'::regclass) order by relname").fetchall() == acl_before
    pg.execute("delete from auth_api_keys where report_subject_id=any(%s)", (list(ids.values()),))
    pg.execute("delete from access_audit_v4 where subject_id=any(%s)", (list(ids.values()),))
    assert {row["id"]: row["is_service"] for row in pg.execute("select id,is_service from auth_users")} == observed
