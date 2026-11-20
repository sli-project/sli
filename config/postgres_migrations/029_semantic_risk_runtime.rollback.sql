-- Roll back SEMANTIC-RISK-RUNTIME-1 only before policy/runtime state exists.

begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_semantic_risk_runtime_v29'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'rollback 029 requires membership in adlog_storage_owner';
    end if;
    if exists (select 1 from semantic_risk_policies)
       or exists (select 1 from semantic_risk_policy_subscriptions)
       or exists (select 1 from semantic_control_health_observations)
       or exists (select 1 from semantic_risk_evaluation_jobs)
       or exists (select 1 from semantic_risk_evaluation_results) then
        raise exception 'rollback 029 refused: semantic risk runtime data exists';
    end if;
end
$$;

set local role adlog_storage_owner;

drop index if exists idx_semantic_risk_result_metrics;
drop index if exists idx_semantic_risk_evaluation_source;
drop index if exists idx_semantic_risk_evaluation_claim;
drop index if exists idx_semantic_control_health_latest;
drop index if exists idx_semantic_risk_subscription_source;
drop trigger if exists trg_semantic_risk_result_immutability on semantic_risk_evaluation_results;
drop function if exists enforce_semantic_risk_result_immutability();
drop table if exists semantic_risk_evaluation_results;
drop table if exists semantic_risk_evaluation_jobs;
drop trigger if exists trg_semantic_control_health_immutability on semantic_control_health_observations;
drop function if exists enforce_semantic_control_health_immutability();
drop table if exists semantic_control_health_observations;
drop trigger if exists trg_semantic_risk_subscription_draft_only on semantic_risk_policy_subscriptions;
drop function if exists enforce_semantic_risk_subscription_draft_only();
drop table if exists semantic_risk_policy_subscriptions;
drop trigger if exists trg_semantic_risk_policy_immutability on semantic_risk_policies;
drop function if exists enforce_semantic_risk_policy_immutability();
drop index if exists uq_semantic_risk_policy_enabled;
drop table if exists semantic_risk_policies;

delete from schema_migrations where version=29 and name='semantic_risk_runtime';

commit;
