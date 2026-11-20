-- STAGE8-L1: allow bounded TEST/SHADOW risk evaluation from canonical actions.
-- Source-only. It does not register policies, enable workers or create findings.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_semantic_canonical_action_risk_v53')
);

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 053 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=52 and name='semantic_conclusion_completeness'
    ) then
        raise exception 'migration 053 requires migration 052';
    end if;
end
$$;

set local role adlog_storage_owner;

alter table semantic_risk_policies
    drop constraint if exists semantic_risk_policies_source_kind_check;
alter table semantic_risk_policies
    add constraint semantic_risk_policies_source_kind_check
    check(source_kind in (
        'canonical_action','correlation_candidate','control_health'
    ));

alter table semantic_risk_policy_subscriptions
    drop constraint if exists semantic_risk_policy_subscriptions_source_kind_check;
alter table semantic_risk_policy_subscriptions
    add constraint semantic_risk_policy_subscriptions_source_kind_check
    check(source_kind in (
        'canonical_action','correlation_candidate','control_health'
    ));

alter table semantic_risk_evaluation_jobs
    add column if not exists canonical_action_id uuid
        references canonical_actions(canonical_action_id) on delete restrict;
alter table semantic_risk_evaluation_jobs
    drop constraint if exists semantic_risk_evaluation_jobs_source_kind_check,
    drop constraint if exists semantic_risk_evaluation_source;
alter table semantic_risk_evaluation_jobs
    add constraint semantic_risk_evaluation_jobs_source_kind_check
    check(source_kind in (
        'canonical_action','correlation_candidate','control_health'
    )),
    add constraint semantic_risk_evaluation_source check (
        (
            source_kind='canonical_action'
            and canonical_action_id is not null
            and correlation_candidate_id is null
            and control_health_id is null
            and source_reference=canonical_action_id::text
        )
        or (
            source_kind='correlation_candidate'
            and canonical_action_id is null
            and correlation_candidate_id is not null
            and control_health_id is null
            and source_reference=correlation_candidate_id::text
        )
        or (
            source_kind='control_health'
            and canonical_action_id is null
            and correlation_candidate_id is null
            and control_health_id is not null
            and source_reference=control_health_id::text
        )
    );

create index if not exists idx_semantic_risk_evaluation_action
    on semantic_risk_evaluation_jobs(canonical_action_id)
    where canonical_action_id is not null;

insert into schema_migrations(version,name)
values(53,'semantic_canonical_action_risk')
on conflict(version) do update set name=excluded.name,applied_at=now();

commit;
