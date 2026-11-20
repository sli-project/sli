-- Built-in L1 detection policies publish problems out of the box. A small
-- business has no one to admit them by hand; until now SLI saw the attack and
-- stayed silent. An explicit owner choice (any existing admission row) wins.
begin;
select pg_advisory_xact_lock(hashtext('sli_default_policy_admission_v256'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=255 and name='workstation_protection_predecessor')
       or exists(select 1 from public.schema_migrations where version>=256) then
        raise exception 'migration 256 prerequisites failed';
    end if;
end $$;
set local role adlog_storage_owner;
set local lock_timeout='5s';

-- The admission trigger writes the semantic_control_audit receipt.
insert into public.semantic_policy_admission(policy_id,policy_version,enabled,updated_by)
select policy.policy_id,policy.policy_version,true,'system:defaults'
from public.semantic_risk_policies policy
where policy.policy_id in ('l1-audit-policy-changed','l1-eventlog-cleared',
                           'l1-privileged-group-member-added','l1-scheduled-task-created')
  and policy.policy_version=2
  and policy.lifecycle_status in ('shadow','enabled')
on conflict (policy_id,policy_version) do nothing;

-- Jobs quarantined only because admission was missing get one audited retry.
with candidates as materialized (
    select job.job_id,job.attempt_count,job.max_attempts,job.updated_at
    from public.semantic_risk_evaluation_jobs job
    join public.semantic_risk_policies policy using(policy_id,policy_version)
    join public.semantic_policy_admission admission using(policy_id,policy_version)
    where job.evaluation_status='quarantined' and job.source_kind='canonical_action'
      and job.evaluation_mode='enabled'
      and admission.enabled is true and admission.updated_by='system:defaults'
      and public.semantic_policy_mode_v160(policy.policy_id,policy.policy_version,policy.lifecycle_status)='enabled'
      and job.last_error_code='RuntimeError'
      and job.last_error_detail='semantic finding requires an observed enabled result'
      and not exists(select 1 from public.semantic_risk_evaluation_results result where result.job_id=job.job_id)
      and not exists(select 1 from public.semantic_control_audit audit
          where audit.action='semantic_risk_quarantine_requeue_v256' and audit.target=job.job_id::text)
    order by job.updated_at,job.job_id
    for update of job
), requeued as (
    update public.semantic_risk_evaluation_jobs job
    set evaluation_status='queued',attempt_count=0,available_at=now(),
        lease_token=null,lease_until=null,heartbeat_at=null,completed_at=null,
        last_error_code=null,last_error_detail=null,updated_at=now()
    from candidates old where job.job_id=old.job_id
    returning job.job_id
)
insert into public.semantic_control_audit(action,target,actor,details)
select 'semantic_risk_quarantine_requeue_v256',old.job_id::text,'migration:256',
       jsonb_build_object('outcome','requeued','reason','default_admission',
           'original_attempt_count',old.attempt_count,'original_max_attempts',old.max_attempts,
           'original_quarantined_at',old.updated_at)
from candidates old join requeued using(job_id);

reset role;
insert into public.schema_migrations(version,name) values(256,'default_policy_admission');
commit;
