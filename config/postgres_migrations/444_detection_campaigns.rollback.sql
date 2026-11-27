begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_detection_campaigns444'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=444 and name='detection_campaigns')
       or exists(select 1 from public.schema_migrations where version>444) then
        raise exception 'detection_campaigns444_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

-- The former publisher requires the scenario fingerprint. Do not invalidate
-- immutable publications written by the new publisher.
do $$ begin
    if exists (
        select 1 from public.problem_campaign_sources444 source
        join public.semantic_finding_publications p using(scenario_id)
        join public.semantic_security_scenarios s using(scenario_id)
        where p.finding_fingerprint<>'semantic:'||encode(s.scenario_key,'hex')
    ) then raise exception 'detection_campaigns444_rollback_has_grouped_publications' using errcode='55000'; end if;
end $$;

do $$ declare saved record; begin
    for saved in select definition from public.problem_campaign_functions_restore444 loop
        execute saved.definition;
    end loop;
end $$;

update public.semantic_identity_attack_episodes_v301 e set password_finding418=r.prior_finding
from public.problem_campaign_episodes_restore444 r
where (e.scope_key,e.rule_id,e.entity_key,e.episode_key)=(r.scope_key,r.rule_id,r.entity_key,r.episode_key)
  and e.password_finding418=r.survivor_id;

reset role;
with reopened as (
    update public.findings f set status=r.status,status_reason=r.reason,closed_at=r.closed,updated_at=r.updated
    from public.problem_campaign_findings_restore444 r
    where f.id=r.finding_id and r.finding_id<>r.survivor_id and f.status='closed'
      and f.updated_at=r.changed_at and f.status_reason='problem_campaign_merged444:'||r.survivor_id
    returning r.history_id
)
delete from public.finding_status_history h using reopened r where h.id=r.history_id and h.changed_by='SLI';

update public.findings f set first_seen_utc=r.first_seen,last_seen_utc=r.last_seen,
    severity=r.severity,password_threshold_facts418=r.facts,updated_at=r.updated
from public.problem_campaign_findings_restore444 r
where f.id=r.finding_id and r.finding_id=r.survivor_id and f.updated_at=r.changed_at;

set local role adlog_storage_owner;
drop function public.problem_campaign_route444(uuid,bigint),public.password_campaign_facts444(bigint,boolean),
    public.password_campaign_key444(text,bigint,jsonb),public.audit_campaign_key444(jsonb,jsonb),
    public.expire_password_campaigns444(),public.close_quiet_password_campaigns444(text,timestamptz);
drop table public.problem_campaign_sources444,public.problem_campaigns444,
    public.problem_campaign_functions_restore444,public.problem_campaign_findings_restore444,
    public.problem_campaign_episodes_restore444;
delete from public.schema_migrations where version=444 and name='detection_campaigns';
reset role;
commit;
