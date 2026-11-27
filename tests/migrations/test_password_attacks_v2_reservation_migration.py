"""Lifetime storage: actual native candidate costs, immutable history and atomic PG guards.

Owner-only historical/next-State fixtures explicitly model the absent B2 coordinator;
no public State success or independently SQL-verified detector semantics is claimed.
"""
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from uuid import NAMESPACE_URL, uuid5

import pytest

from tests.migrations.test_password_attacks_v2_migration import _connection, _replace_xml, _xml, acl_pg as acl_pg, native_pg as native_pg, password_base_pg as password_base_pg

pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]
BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)
POLICY = "fixture-password-storage"


def _ledger(admin):
    row = admin.execute("select * from semantic_password_episode_budgets").fetchone()
    return dict(last_sequence=row["last_sequence"], last_emission_id=row["last_emission_id"],
        ref_occurrences=row["reserved_ref_occurrences"], portions=row["reserved_portions"], xml_bytes=row["reserved_xml_bytes"])


            # Roll back the intentionally orphan staged row; public direct COMMIT
            # completeness rejection is independently exercised above.


def test_lifetime_new_private_objects_revoke_real_default_report_grants(password_base_pg):
    import psycopg
    from pathlib import Path
    from psycopg.rows import dict_row
    path = Path(__file__).resolve().parents[2] / "config/postgres_migrations/273_password_attacks_v2.sql"
    with psycopg.connect(password_base_pg, autocommit=True, row_factory=dict_row) as admin:
        admin.execute("alter default privileges for role adlog_storage_owner in schema public grant select on tables to adlog_user")
        admin.execute("alter default privileges for role adlog_storage_owner in schema public grant execute on functions to adlog_user")
        try:
            admin.execute(path.read_text("utf-8"))
            assert not admin.execute("select has_table_privilege('adlog_user','semantic_password_episode_budgets','SELECT') as yes").fetchone()["yes"]
            for function in ("password_v2_qw_index_key()", "password_v2_decode(jsonb,jsonb,jsonb)", "lock_password_publication_v2(jsonb,jsonb,text)"):
                assert not admin.execute("select has_function_privilege('adlog_user',%s,'EXECUTE') as yes", (function,)).fetchone()["yes"]
        finally:
            admin.execute("alter default privileges for role adlog_storage_owner in schema public revoke select on tables from adlog_user")
            admin.execute("alter default privileges for role adlog_storage_owner in schema public revoke execute on functions from adlog_user")


def _order(admin, episode_key):
    return admin.execute("""select first_ledger_revision,admitted_revision,last_sequence,frozen
        from semantic_password_episode_budgets where episode_key=%s""", (episode_key,)).fetchone()


def _expected_ledger(admin, episode_key):
    row = admin.execute("select * from semantic_password_episode_budgets where episode_key=%s", (episode_key,)).fetchone()
    return dict(last_sequence=row["last_sequence"], last_emission_id=row["last_emission_id"],
        ref_occurrences=row["reserved_ref_occurrences"], portions=row["reserved_portions"], xml_bytes=row["reserved_xml_bytes"])
