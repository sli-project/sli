"""Canonical password state/health boundary on guarded synthetic PostgreSQL."""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from uuid import uuid4

import pytest

from tests.migrations.test_password_attacks_v2_migration import AGENT, _connection, acl_pg as acl_pg, native_pg as native_pg, password_base_pg as password_base_pg


ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/273_password_attacks_v2.sql"
pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]


def _call(conn, name, *args):
    placeholders = ",".join(["%s::jsonb"] * len(args))
    return conn.execute(f"select public.{name}({placeholders}) as result",
                        tuple(json.dumps(item) for item in args)).fetchone()["result"]


def _bucket(hour, count, minimum, maximum):
    return {"hour": hour, "count": count, "observed_min": minimum.isoformat(), "observed_max": maximum.isoformat(),
            "from": "2026-01-01T00:00:00+00:00", "to": "2026-01-01T00:10:00+00:00"}


def test_state_objects_rollback_with_unpublished_migration(password_base_pg):
    import psycopg
    import psycopg.rows
    marker = "insert into public.schema_migrations(version,name) values(273,'password_attacks_v2');"
    with psycopg.connect(password_base_pg, autocommit=True, row_factory=psycopg.rows.dict_row) as admin:
        with pytest.raises(psycopg.errors.DivisionByZero):
            admin.execute(PATH.read_text("utf-8-sig").replace(marker, "select 1/0;\n" + marker))
        admin.execute("rollback")
        for obj in ("semantic_password_checkpoints", "semantic_password_window_members", "semantic_password_attempt_seq"):
            assert admin.execute("select to_regclass(%s) as value", ("public." + obj,)).fetchone()["value"] is None


def test_new_private_tables_revoke_existing_report_reader_default_grants(password_base_pg):
    import psycopg
    with psycopg.connect(password_base_pg, autocommit=True) as admin:
        admin.execute("alter default privileges for role adlog_storage_owner in schema public grant select,insert on tables to adlog_user")
        admin.execute(PATH.read_text("utf-8-sig"))
        for table in ("semantic_password_checkpoints", "semantic_password_window_members"):
            for privilege in ("SELECT", "INSERT"):
                assert not admin.execute("select has_table_privilege('adlog_user',%s,%s)",
                                         ("public." + table, privilege)).fetchone()[0]
