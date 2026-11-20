-- Preserve the accepted legacy enabled policy when publication requires an
-- explicit admission. Never promote shadow policies or override a revocation.
begin;
select pg_advisory_xact_lock(hashtext('sli_semantic_legacy_admission_v257'));
set local lock_timeout='5s';
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations
           where version=255 and name='workstation_protection_predecessor')
       or not exists(select 1 from public.schema_migrations
           where version=246 and name='semantic_throughput')
       or exists(select 1 from public.schema_migrations where version>=257) then
        raise exception 'migration 257 prerequisites failed';
    end if;
end $$;
set local role adlog_storage_owner;

-- Admission edits and publication serialize on the same policy row. The
-- existing admission trigger supplies the immutable policy_admission receipt.
select policy_id from public.semantic_risk_policies
where policy_id='l1-audit-policy-changed' and policy_version=2
for update;
insert into public.semantic_policy_admission(policy_id,policy_version,enabled,updated_by)
select policy_id,policy_version,true,'migration:257:legacy-enabled-policy'
from public.semantic_risk_policies
where policy_id='l1-audit-policy-changed' and policy_version=2
  and source_kind='canonical_action' and lifecycle_status='enabled'
on conflict(policy_id,policy_version) do nothing;

-- Migration 246 could not recover these jobs while admission was missing.
-- Retry only its exact known publication failure, with no committed result.
with candidates as materialized (
    select job.job_id,job.attempt_count,job.max_attempts,job.last_error_code,
           job.last_error_detail,job.updated_at
    from public.semantic_risk_evaluation_jobs job
    join public.semantic_risk_policies policy using(policy_id,policy_version)
    join public.semantic_policy_admission admission using(policy_id,policy_version)
    where policy.policy_id='l1-audit-policy-changed' and policy.policy_version=2
      and policy.source_kind='canonical_action' and policy.lifecycle_status='enabled'
      and admission.enabled is true
      and job.evaluation_status='quarantined' and job.source_kind='canonical_action'
      and job.evaluation_mode='enabled' and job.attempt_count>=job.max_attempts
      and job.last_error_code='RuntimeError'
      and job.last_error_detail='semantic finding requires an observed enabled result'
      and not exists(select 1 from public.semantic_risk_evaluation_results result
          where result.job_id=job.job_id)
      and not exists(select 1 from public.semantic_control_audit audit
          where audit.action='semantic_risk_quarantine_requeue_v257'
            and audit.target=job.job_id::text)
    order by job.updated_at,job.job_id
    limit 128 for update of job skip locked
), requeued as (
    update public.semantic_risk_evaluation_jobs job
    set evaluation_status='queued',attempt_count=0,available_at=now(),
        lease_token=null,lease_until=null,heartbeat_at=null,completed_at=null,
        last_error_code=null,last_error_detail=null,updated_at=now()
    from candidates old where job.job_id=old.job_id
    returning job.job_id
)
insert into public.semantic_control_audit(action,target,actor,details)
select 'semantic_risk_quarantine_requeue_v257',old.job_id::text,'migration:257',
       jsonb_build_object(
           'outcome','requeued','reason','legacy_enabled_admission_restored',
           'original_attempt_count',old.attempt_count,'original_max_attempts',old.max_attempts,
           'original_error_code',old.last_error_code,
           'original_error_detail_sha256',encode(sha256(convert_to(old.last_error_detail,'UTF8')),'hex'),
           'original_quarantined_at',old.updated_at
       )
from candidates old join requeued using(job_id);

reset role;
insert into public.schema_migrations(version,name) values(257,'semantic_legacy_admission');
commit;
