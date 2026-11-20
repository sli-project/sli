begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_semantic_canonical_action_risk_v53')
);

do $$
begin
    if exists(select 1 from schema_migrations where version>53) then
        raise exception 'rollback 053 refused: later migrations exist';
    end if;
    if exists(
        select 1 from semantic_risk_policies
        where source_kind='canonical_action'
    ) or exists(
        select 1 from semantic_risk_evaluation_jobs
        where source_kind='canonical_action'
    ) then
        raise exception 'rollback 053 refused: canonical-action risk evidence exists';
    end if;
end
$$;

set local role adlog_storage_owner;

drop index if exists idx_semantic_risk_evaluation_action;
alter table semantic_risk_evaluation_jobs
    drop constraint if exists semantic_risk_evaluation_source,
    drop constraint if exists semantic_risk_evaluation_jobs_source_kind_check,
    drop column if exists canonical_action_id;
alter table semantic_risk_evaluation_jobs
    add constraint semantic_risk_evaluation_jobs_source_kind_check
    check(source_kind in ('correlation_candidate','control_health')),
    add constraint semantic_risk_evaluation_source check (
        (
            source_kind='correlation_candidate'
            and correlation_candidate_id is not null
            and control_health_id is null
            and source_reference=correlation_candidate_id::text
        )
        or (
            source_kind='control_health'
            and correlation_candidate_id is null
            and control_health_id is not null
            and source_reference=control_health_id::text
        )
    );

alter table semantic_risk_policy_subscriptions
    drop constraint if exists semantic_risk_policy_subscriptions_source_kind_check;
alter table semantic_risk_policy_subscriptions
    add constraint semantic_risk_policy_subscriptions_source_kind_check
    check(source_kind in ('correlation_candidate','control_health'));

alter table semantic_risk_policies
    drop constraint if exists semantic_risk_policies_source_kind_check;
alter table semantic_risk_policies
    add constraint semantic_risk_policies_source_kind_check
    check(source_kind in ('correlation_candidate','control_health'));

delete from schema_migrations
where version=53 and name='semantic_canonical_action_risk';

commit;
