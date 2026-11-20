"""Registered security event grants agree with the dataset without widening scope."""
import json
import os
from pathlib import Path

import pytest

from tests.postgres_integration_guard import assert_disposable_database

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_identity_category_preserves_report_fields_actions_and_other_datasets():
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    with psycopg.connect(os.environ["ADLOG_TEST_PG_DSN"], autocommit=True, row_factory=dict_row) as conn:
        assert_disposable_database(conn)
        conn.execute("""do $$ begin
            if to_regrole('adlog_storage_owner') is null then create role adlog_storage_owner nologin; end if;
            end $$;
            create table schema_migrations(version int primary key,name text);
            insert into schema_migrations values(204,'agent_gpo_history_slot_timestamp');
            create table report_datasets_v4(id int primary key,dataset_key text,version int,fields_json jsonb);
            create table report_registry_v4(report_key text,version int,dataset_id int,definition_json jsonb);""")
        fields = [{"key": key, "category": category} for key, category in (
            ("actor", "security"), ("affected_account", "security"),
            ("member", "security"), ("group", "security"), ("outcome", "security"),
            ("event_id", "technical"), ("evidence", "raw_evidence"))]
        definition = {"field_categories": ["identity_basic", "security", "technical", "raw_evidence"],
                      "actions": ["view", "export", "start_case"], "columns": fields}
        conn.execute("insert into report_datasets_v4 values(1,'security.events.atomic',1,%s::jsonb),"
                     "(2,'other',1,%s::jsonb)", (json.dumps(fields), json.dumps(fields)))
        conn.execute("insert into report_registry_v4 values('security.events.chains',1,1,%s::jsonb)",
                     (json.dumps(definition),))
        conn.execute((ROOT / "config/postgres_migrations/205_security_event_identity_category.sql").read_text("utf-8"))
        updated = conn.execute("select definition_json from report_registry_v4").fetchone()["definition_json"]
        categories = {field["category"] for field in updated["columns"]}
        assert categories == set(updated["field_categories"])
        assert updated["actions"] == definition["actions"]
        assert [field["key"] for field in updated["columns"]] == [field["key"] for field in fields]
        assert conn.execute("select fields_json from report_datasets_v4 where id=2").fetchone()["fields_json"] == fields
        assert conn.execute("select name from schema_migrations where version=205").fetchone()["name"] == "security_event_identity_category"
