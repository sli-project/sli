"""Additive migration contracts; never connect to a database."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def sql():
    return (ROOT / "config/postgres_migrations/162_finding_risk_acceptance.sql").read_text(encoding="utf-8")


def test_reuses_scoped_suppressions_and_retains_existing_audit_trigger():
    text = sql()
    assert "create table" not in text.lower()
    assert "alter table semantic_suppressions" in text
    assert "references auth_users(id)" in text
    assert "references findings(id)" in text
    assert "risk_acceptance" in text and "responsible_user_id is not null" in text
    assert "unique index" in text and "where kind='risk_acceptance' and state='active'" in text
    assert "drop trigger semantic_suppressions_audit" not in text
    assert "values(162,'finding_risk_acceptance')" in text


def test_expiry_and_revocation_restore_attention_and_history_in_same_transaction():
    text = sql()
    assert "new.state in ('expired','revoked')" in text
    assert "coalesce(repeat_count,0)>0 then 'repeated' else 'new'" in text
    assert "insert into public.finding_status_history" in text
    assert "new.changed_by" in text
    assert "security definer set search_path=pg_catalog,public" in text
    assert "revoke all on function finding_risk_return_v162() from public" in text
    assert "grant insert on semantic_control_audit" not in text
