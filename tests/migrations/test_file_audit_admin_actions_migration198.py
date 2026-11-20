"""The file-audit owner command must commit both audit records on PostgreSQL."""
import os
import re
from pathlib import Path

import psycopg
import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/198_file_audit_admin_actions.sql"
SQL = PATH.read_text("utf-8")


def test_migration_preserves_prior_actions_and_has_exact_predecessor():
    pairs = [(m.version, m.name) for m in forward_migration_inventory(PATH.parent)]
    index = pairs.index((198, "file_audit_admin_actions"))
    assert pairs[index - 1] == (197, "workstation_file_audit")
    assert len(pairs) == len({version for version, _ in pairs})
    assert list(PATH.parent.glob("198_*.sql")) == [PATH]
    assert "version=197 and name='workstation_file_audit'" in SQL
    assert "version>=198" in SQL
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in SQL
    assert "pg_get_expr(conbin,conrelid) into strict previous" in SQL
    assert "check ((%s) or action in" in SQL
    assert not re.search(r"grant |revoke |delete from|truncate |update public\.", SQL, re.IGNORECASE)
    for source in ("server/sli/plugins/file_audit/management.py", "server/sli/agents/file_audit_admin.py"):
        action = re.search(r'registry.audit\(cur, "([a-z_]+)"', (ROOT / source).read_text("utf-8"))[1]
        assert f"''{action}''" in SQL


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_real_constraint_accepts_both_audits_preserves_old_rows_and_rejects_unknown():
    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("isolated PostgreSQL template is not configured")
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("create table schema_migrations(version integer primary key, name text)")
        conn.execute("insert into schema_migrations values(197,'wrong_predecessor')")
        conn.execute("create table sli_agent_audit(action text not null constraint sli_agent_audit_action_check "
                     "check(action in ('issue','policy_update','future_existing_action')))")
        conn.execute("alter table sli_agent_audit owner to adlog_storage_owner")
        conn.execute("insert into sli_agent_audit values('issue')")
        with pytest.raises(psycopg.errors.RaiseException, match="requires exact migration 197"):
            conn.execute(SQL)
        conn.execute("rollback")
        conn.execute("update schema_migrations set name='workstation_file_audit' where version=197")
        conn.execute(SQL)
        for action in ('policy_update', 'future_existing_action', 'file_audit_command', 'local_file_audit_command'):
            conn.execute("insert into sli_agent_audit values(%s)", (action,))
        assert conn.execute("select action from sli_agent_audit").fetchall() == [
            ('issue',), ('policy_update',), ('future_existing_action',), ('file_audit_command',), ('local_file_audit_command',)]
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute("insert into sli_agent_audit values('unknown_action')")
        assert conn.execute("select name from schema_migrations where version=198").fetchone() == ('file_audit_admin_actions',)
        with pytest.raises(psycopg.errors.RaiseException, match="unused version 198"):
            conn.execute(SQL)
        conn.execute("rollback")
