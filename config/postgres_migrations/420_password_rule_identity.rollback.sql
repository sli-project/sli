begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_password_threshold418'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=420 and name='password_rule_identity')
       or exists(select 1 from public.schema_migrations where version>420) then
        raise exception 'password_rule_identity420_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

do $$ declare saved record; begin
    for saved in select definition from public.password_rule_functions_restore420 loop
        execute saved.definition;
    end loop;
end $$;
drop function public.password_threshold_domain420(jsonb);
drop table public.password_rule_functions_restore420;

delete from public.semantic_identity_attack_episodes_v301
where rule_id='qw.password-brute-force' and scope_key like 'password-domain:%';

update public.semantic_security_scenarios s set partition_key=r.partition_key,identity_key=r.identity_key,
    strict_keys_json=r.strict_keys,
    risk_class=case when f.updated_at=b.changed_at then r.risk_class else s.risk_class end
from public.password_rule_scenarios_restore420 r
join public.password_rule_findings_restore420 b on b.finding_id=b.survivor_id
join public.findings f on f.id=b.finding_id
where s.scenario_id=r.scenario_id and f.fingerprint='semantic:'||encode(s.scenario_key,'hex');

reset role;

-- Reverse the migration's own decisions. Respect any subsequent decision
-- or evidence publication on a finding.
with reopened as (
    update public.findings f set status=r.prior_status,status_reason=r.prior_reason,
        closed_at=r.prior_closed,updated_at=r.prior_updated
    from public.password_rule_findings_restore420 r
    where f.id=r.finding_id and f.status='closed' and f.closed_at::timestamptz=r.changed_at
      and f.status_reason=case when r.survivor_id is null then 'password_rule_replaced420'
          else 'password_rule_merged420:'||r.survivor_id end
    returning r.history_id
)
delete from public.finding_status_history h using reopened r where h.id=r.history_id and h.changed_by='SLI';

delete from public.finding_event_copies337 c using public.password_rule_findings_restore420 r,public.findings f
where c.finding_id=r.finding_id and r.finding_id=r.survivor_id and f.id=r.finding_id
  and c.evidence_role='semantic_scenario' and f.updated_at=r.changed_at
  and exists (select 1 from public.password_rule_evidence_restore420 b where b.finding_id=c.finding_id);
insert into public.finding_event_copies337
select c.* from public.password_rule_evidence_restore420 c join public.password_rule_findings_restore420 r on r.finding_id=c.finding_id
join public.findings f on f.id=c.finding_id and f.updated_at=r.changed_at on conflict do nothing;

update public.findings f set first_seen_utc=r.prior_first,last_seen_utc=r.prior_last,severity=r.prior_severity,
    evidence_count=r.prior_count,last_evidence_event_id=r.prior_event,password_threshold_facts418=r.prior_facts,updated_at=r.prior_updated
from public.password_rule_findings_restore420 r
where f.id=r.finding_id and r.finding_id=r.survivor_id and f.updated_at=r.changed_at;

set local role adlog_storage_owner;
drop table public.password_rule_findings_restore420,public.password_rule_scenarios_restore420,public.password_rule_evidence_restore420;
delete from public.schema_migrations where version=420 and name='password_rule_identity';
reset role;
commit;
