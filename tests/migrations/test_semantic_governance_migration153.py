"""Source contracts for migration 153. These checks never apply migrations."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SQL = (ROOT / "config/postgres_migrations/153_semantic_governance.sql").read_text(encoding="utf-8")


def test_requires_exact_plugin_state_predecessor_before_creating_objects():
    preflight = SQL.split("set local role adlog_storage_owner;")[0]
    assert "not exists(select 1 from schema_migrations where version=152 and name='plugin_state')" in preflight
    assert "raise exception 'migration 153 requires exact migration 152 plugin_state'" in preflight
    assert "version=153 and name <> 'semantic_governance'" in preflight


def test_additive_governance_schema_and_immutable_audit():
    assert "values(153,'semantic_governance')" in SQL
    assert "foreign key(policy_id,policy_version) references semantic_risk_policies" in SQL
    assert "interval '2160 hours'" in SQL
    assert "scope_kind in ('subject_sid','bucket')" in SQL
    assert "length(trim(reason)) between 1 and 2000" in SQL
    assert "create trigger semantic_suppressions_audit after insert or update" in SQL
    assert "create trigger semantic_policy_admission_audit after insert or update" in SQL
    assert "case when new.state='expired' then new.expires_at" in SQL
    assert "from public" in SQL
    assert "grant select on semantic_risk_policies,semantic_control_audit" in SQL
    audit_grants = [grant for grant in re.findall(r"grant\s+[^;]+;", SQL) if "semantic_control_audit" in grant]
    assert audit_grants == ["grant select on semantic_risk_policies,semantic_control_audit to adlog_user;"]
    assert "delete from" not in SQL.lower()


def test_bounded_read_only_review_uses_explicit_context_not_process_guessing():
    reader = SQL.split("create function semantic_finding_review_v160")[1].split("create function semantic_finding_suppressed_v160")[0]
    assert "limit 21" in reader
    assert "limit 1" in reader
    assert "'kind','hint','verdict',false" in reader
    assert "g.correlation_id=s.correlation_id" in reader
    assert "provider.value='Microsoft-Windows-GroupPolicy'" in reader
    assert "facts.logon_type in ('2','10')" in reader
    assert "privilege.subject_user_sid=s.subject_user_sid" in reader
    assert "privilege.logon_id=s.logon_id" in reader
    assert "g.domain_id=s.domain_id" in reader
    assert all(word not in reader.lower() for word in ("update ", "insert ", "delete "))


def test_suppression_is_exact_and_expiry_does_not_depend_on_sweeper():
    matcher = SQL.split("create function semantic_finding_suppressed_v160")[1].split("revoke all")[0]
    assert "rule.expires_at > statement_timestamp()" in matcher
    assert "rule.semantic_type=p_type" in matcher
    assert "rule.domain_id=(hint->>'domain_id')::bigint" in matcher
    assert "rule.scope_value=hint->>'subject_sid'" in matcher
    assert "rule.scope_value=hint->>'bucket'" in matcher
    assert "(hint->>'truncated')::boolean is false" in matcher
    assert "e.subject_user_sid is distinct from hint->>'subject_sid'" in matcher
    expiry = SQL.split("create function expire_semantic_suppressions_v160")[1].split("create function semantic_policy_mode_v160")[0]
    assert "for update skip locked limit 100" in expiry
    assert "changed_by='system:expiry'" in expiry


def test_admission_preserves_default_lifecycle_and_worker_cannot_write_overrides():
    mode = SQL.split("create function semantic_policy_mode_v160")[1].split("create function semantic_finding_review_v160")[0]
    assert "when p_state not in ('test','shadow','enabled') then null" in mode
    assert "when a.enabled is false then null" in mode
    assert "a.enabled is true and p_state in ('shadow','enabled') then 'enabled'" in mode
    assert "else p_state end" in mode
    assert "insert into semantic_policy_admission" not in SQL
    assert "grant select on semantic_policy_admission to adlog_semantic_worker" in SQL
