"""No runtime database: verify the bounded role and publication gate contract."""
from pathlib import Path


def test_delivery_role_and_severity_gate():
    sql = (Path(__file__).resolve().parents[2] / "config/postgres_migrations/261_telegram_delivery.sql").read_text()
    assert "version=259 and name='admin_problem_evidence'" in sql
    assert "nologin noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls" in sql
    assert "grant select(id,username,role,is_active) on public.auth_users" in sql
    assert "grant references on public.access_audit_v4" in sql
    assert "grant select on public.access_audit_v4" not in sql
    assert "grant insert on public.notification_attempts" in sql
    assert "grant insert on public.notification_outbox" not in sql
    assert "before insert on public.notification_outbox" in sql
    assert "new.object_severity is distinct from 'high'" in sql
    assert "new.object_severity is distinct from 'critical'" in sql
