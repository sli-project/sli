-- Fresh Linux baseline only, in the same transaction as schema bootstrap.
-- Keep the canonical JSON/hash and selector aligned with the runtime compiler.
-- pg_dump leaves search_path empty; the subscription trigger resolves the
-- policy table through the caller's path. Scope this to bootstrap's transaction.
SET LOCAL search_path = pg_catalog, public;

with definition(document) as (values (
    $policy${"allowed_lateness_seconds":60,"expected_evidence_count":1,"explanation":"Exact named EventData from Event 4719 was observed","merge_window_seconds":300,"required_controls":[],"result_class":"security_incident","risk":{"class":"high","display_points":75,"hard_critical":false,"rationale":"Bounded Stage-8 L1 SHADOW policy match","raw_score":"75"},"scenario_kind":"security.audit_controls_changed","source_selector":{"action_kind":"audit.policy.changed"},"strict_roles":["source_host","actor"],"title":"Audit policy was changed","type":"scenario_policy"}$policy$::text
))
insert into public.semantic_risk_policies
    (policy_id, policy_version, source_kind, lifecycle_status, definition_json, definition_sha256)
select 'l1-audit-policy-changed', 2, 'canonical_action', 'draft',
       document::jsonb, sha256(convert_to(document, 'UTF8'))
from definition;

-- Subscriptions are writable only while the policy is draft.
insert into public.semantic_risk_policy_subscriptions
    (policy_id, policy_version, source_kind, selector_value, definition_sha256)
select policy_id, policy_version, source_kind, 'audit.policy.changed', definition_sha256
from public.semantic_risk_policies
where policy_id = 'l1-audit-policy-changed' and policy_version = 2;

update public.semantic_risk_policies set lifecycle_status = 'enabled'
where policy_id = 'l1-audit-policy-changed' and policy_version = 2;
