"""The repair is bounded to existing entities and trusted directory versions."""
from pathlib import Path
import re

PATH = Path(__file__).resolve().parents[2] / "config/postgres_migrations/213_ad_directory_display_names.sql"


def test_name_repair_uses_latest_completed_directory_observation_of_same_entity():
    sql = PATH.read_text("utf-8")
    for fragment in (
        "version=212 and name='file_audit_page_evidence'", "version>=213",
        "version.source_section='directory_accounts'", "run.status='completed'", "section.status='complete'",
        "run.domain_id=entity.domain_id", "version.entity_id=entity.id",
        "order by version.last_observed_at_utc desc,version.id desc", "limit 1",
        "entity.display_name ~ '^ad:.*:exact-logon$'", "entity_type.value in ('ad_user','ad_computer')",
        "nullif(btrim", "update public.entities_v2", "where entity.id=repair.entity_id",
        "values(213,'ad_directory_display_names')",
    ):
        assert fragment in sql
    assert not re.search(r"insert into (?:public\.)?(?:entities_v2|ad_context_entity_versions)\b", sql, re.I)
    assert not re.search(r"\b(?:delete from|truncate|create table|create role)\b", sql, re.I)
    assert not re.search(r"grant .*?to (?:public|adlog_user)\s*;", sql, re.I)


def test_name_repair_is_atomic_and_rehashes_materialized_names():
    sql = PATH.read_text("utf-8")
    assert sql.startswith("--") and "\nbegin;" in sql and sql.rstrip().endswith("commit;")
    assert "pg_advisory_xact_lock" in sql
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in sql
    assert "set local role adlog_storage_owner" in sql
    assert "source_core_sha256=sha256" in sql
    assert "source_details_sha256=sha256" in sql
    assert sql.index("update public.entities_v2") < sql.index("values(213,")
