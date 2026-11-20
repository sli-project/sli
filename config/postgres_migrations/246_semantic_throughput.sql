-- Bound risk discovery and retain an audited retry only after explicit admission.
begin;
select pg_advisory_xact_lock(hashtext('sli_semantic_throughput_v246'));

do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=245 and name='file_decoy')
       or exists(select 1 from public.schema_migrations where version>=246) then
        raise exception 'migration 246 prerequisites failed';
    end if;
end $$;
set local role adlog_storage_owner;
set local lock_timeout='5s';

-- The existing action-kind index has mixed descending/ascending order. The
-- lateral backlog query needs this exact order to stop at its per-policy limit.
create index idx_canonical_actions_risk_fifo
    on public.canonical_actions(action_kind,occurred_at_utc,canonical_action_id)
    where action_status not in ('contradicted','superseded','quarantined');

-- Hourly completion metrics must not read every wide outbox row under load.
create index idx_semantic_outbox_completed_at
    on public.semantic_processing_outbox(completed_at) where status='completed';

-- No admission is created here. Missing/revoked admission remains quarantined.
-- A policy lock serializes against admission edits; busy policies/jobs are skipped.
with candidates as materialized (
    select job.job_id,job.attempt_count,job.max_attempts,job.last_error_code,
           job.last_error_detail,job.updated_at
    from public.semantic_risk_evaluation_jobs job
    join public.semantic_risk_policies policy using(policy_id,policy_version)
    join public.semantic_policy_admission admission using(policy_id,policy_version)
    where job.evaluation_status='quarantined' and job.source_kind='canonical_action'
      and job.evaluation_mode='enabled' and job.attempt_count>=job.max_attempts
      and admission.enabled is true
      and public.semantic_policy_mode_v160(policy.policy_id,policy.policy_version,policy.lifecycle_status)='enabled'
      and job.last_error_code='RuntimeError'
      and job.last_error_detail='semantic finding requires an observed enabled result'
      and not exists(select 1 from public.semantic_risk_evaluation_results result where result.job_id=job.job_id)
      and not exists(select 1 from public.semantic_control_audit audit
          where audit.action='semantic_risk_quarantine_requeue_v246' and audit.target=job.job_id::text)
    order by job.updated_at,job.job_id
    limit 128 for update of job skip locked for share of policy skip locked
), requeued as (
    update public.semantic_risk_evaluation_jobs job
    set evaluation_status='queued',attempt_count=0,available_at=now(),
        lease_token=null,lease_until=null,heartbeat_at=null,completed_at=null,
        last_error_code=null,last_error_detail=null,updated_at=now()
    from candidates old where job.job_id=old.job_id
    returning job.job_id
)
insert into public.semantic_control_audit(action,target,actor,details)
select 'semantic_risk_quarantine_requeue_v246',old.job_id::text,'migration:246',
       jsonb_build_object(
           'outcome','requeued','reason','explicit_admission_restored',
           'original_attempt_count',old.attempt_count,'original_max_attempts',old.max_attempts,
           'original_error_code',old.last_error_code,
           'original_error_detail_sha256',encode(sha256(convert_to(old.last_error_detail,'UTF8')),'hex'),
           'original_quarantined_at',old.updated_at
       )
from candidates old join requeued using(job_id);

reset role;
insert into public.schema_migrations(version,name) values(246,'semantic_throughput');
commit;
