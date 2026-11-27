from __future__ import annotations

import os
from pathlib import Path

import pytest



@pytest.fixture
def report_db():
    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("Disposable PostgreSQL required")
    import psycopg
    from psycopg.rows import dict_row
    with psycopg.connect(dsn, row_factory=dict_row) as conn:
        conn.execute("DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='adlog_storage_owner') THEN CREATE ROLE adlog_storage_owner NOLOGIN; END IF; END $$")
        conn.execute("""CREATE TABLE schema_migrations(version int primary key,name text);
            INSERT INTO schema_migrations VALUES(180,'report_api_key');
            CREATE TABLE report_datasets_v4(id int primary key,fields_json jsonb);
            INSERT INTO report_datasets_v4 VALUES(1,'[{"key":"entity_id","category":"identity_basic"}]'),(2,'[]');
            CREATE TABLE report_registry_v4(report_key text,version int,status text,dataset_id int,
                definition_json jsonb,request_profile_json jsonb);
            INSERT INTO report_registry_v4 VALUES
                ('ad.state',1,'published',1,'{"field_categories":["identity_basic","technical","security"],"keep":"value"}','{"field_categories":["technical"],"keep":"profile"}'),
                ('ad.state',2,'draft',2,'{"field_categories":["technical"]}','{}'),
                ('other.report',1,'published',2,'{"field_categories":["technical"]}','{}');
            CREATE TABLE access_package_reports(id int,field_categories text[]);
            INSERT INTO access_package_reports VALUES(1,ARRAY['technical']);
            CREATE TABLE access_report_assignments(id int,field_categories text[],scope_json jsonb);
            INSERT INTO access_report_assignments VALUES(1,ARRAY['technical'],'{"kind":"domain","ids":[1275]}')""")
        conn.commit()
        yield conn


MIGRATION = Path("config/postgres_migrations/181_ad_state_privilege_category.sql")


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_published_definition_dataset_and_request_profile_add_privilege_without_grant_expansion(report_db):
    conn = report_db
    unrelated = conn.execute("SELECT * FROM report_registry_v4 WHERE report_key<>'ad.state' OR status='draft' ORDER BY report_key").fetchall()
    grants = conn.execute("SELECT * FROM access_report_assignments").fetchall()
    packages = conn.execute("SELECT * FROM access_package_reports").fetchall()
    conn.commit()
    conn.execute(MIGRATION.read_text())
    row = conn.execute("SELECT * FROM report_registry_v4 WHERE report_key='ad.state' AND status='published'").fetchone()
    assert row["definition_json"]["field_categories"] == ["identity_basic", "technical", "security", "privilege"]
    assert row["definition_json"]["keep"] == "value"
    assert row["request_profile_json"]["field_categories"] == ["technical", "privilege"]
    assert row["request_profile_json"]["keep"] == "profile"
    fields = conn.execute("SELECT fields_json FROM report_datasets_v4 WHERE id=1").fetchone()["fields_json"]
    assert any(field["key"] == "group_id" and field["category"] == "privilege" for field in fields)
    assert conn.execute("SELECT * FROM report_registry_v4 WHERE report_key<>'ad.state' OR status='draft' ORDER BY report_key").fetchall() == unrelated
    assert conn.execute("SELECT * FROM access_report_assignments").fetchall() == grants
    assert conn.execute("SELECT * FROM access_package_reports").fetchall() == packages
    assert conn.execute("SELECT name FROM schema_migrations WHERE version=181").fetchone()["name"] == "ad_state_privilege_category"


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
@pytest.mark.parametrize("state", ["missing_predecessor", "repeat", "already_declared"])
def test_migration_requires_exact_predecessor_and_rejects_repeat_without_duplicates(report_db, state):
    import psycopg
    conn = report_db
    if state == "missing_predecessor":
        conn.execute("DELETE FROM schema_migrations")
    elif state == "repeat":
        conn.execute("INSERT INTO schema_migrations VALUES(181,'ad_state_privilege_category')")
    else:
        conn.execute("UPDATE report_registry_v4 SET definition_json='{" + '"field_categories":["privilege"]' + "}' WHERE report_key='ad.state' AND status='published'")
        conn.execute("UPDATE report_datasets_v4 SET fields_json='[{" + '"key":"group_id","category":"privilege"' + "}]' WHERE id=1")
    conn.commit()
    if state == "already_declared":
        conn.execute(MIGRATION.read_text())
        fields = conn.execute("SELECT fields_json FROM report_datasets_v4 WHERE id=1").fetchone()["fields_json"]
        assert len(fields) == 1
        row = conn.execute("SELECT definition_json FROM report_registry_v4 WHERE report_key='ad.state' AND status='published'").fetchone()
        assert row["definition_json"]["field_categories"] == ["privilege"]
    else:
        with pytest.raises(psycopg.errors.RaiseException):
            conn.execute(MIGRATION.read_text())
        conn.rollback()
