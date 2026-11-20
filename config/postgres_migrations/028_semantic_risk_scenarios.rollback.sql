-- Roll back SEMANTIC-RISK-1 only before any scenario state exists.

begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_semantic_risk_v28'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'rollback 028 requires membership in adlog_storage_owner';
    end if;
    if exists (select 1 from semantic_security_scenarios)
       or exists (select 1 from semantic_scenario_steps)
       or exists (select 1 from semantic_scenario_evidence)
       or exists (select 1 from semantic_risk_contributions)
       or exists (select 1 from semantic_scenario_coverage_history) then
        raise exception 'rollback 028 refused: semantic scenario or risk data exists';
    end if;
end
$$;

set local role adlog_storage_owner;

drop index if exists idx_semantic_scenario_coverage_latest;
drop index if exists idx_semantic_risk_contribution_scenario;
drop index if exists idx_semantic_scenario_evidence_event;
drop index if exists idx_semantic_scenario_step_scenario;
drop index if exists idx_semantic_scenario_partition_time;
drop index if exists idx_semantic_scenario_identity_window;
drop table if exists semantic_scenario_coverage_history;
drop trigger if exists trg_semantic_risk_contribution_immutability
    on semantic_risk_contributions;
drop function if exists enforce_semantic_risk_contribution_immutability();
drop table if exists semantic_risk_contributions;
drop table if exists semantic_scenario_evidence;
drop table if exists semantic_scenario_steps;
drop table if exists semantic_security_scenarios;

delete from schema_migrations
where version=28 and name='semantic_risk_scenarios';

commit;
