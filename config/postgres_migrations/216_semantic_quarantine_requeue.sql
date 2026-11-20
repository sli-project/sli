-- Retry only the historical failures whose canonical/source readers are fixed.
begin;
select pg_advisory_xact_lock(hashtext('sli_semantic_quarantine_requeue_v216'));

do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=215 and name='directory_change_catalog_revision')
       or exists(select 1 from public.schema_migrations where version>=216) then
        raise exception 'migration 216 prerequisites failed';
    end if;
end $$;
set local role adlog_storage_owner;

-- Preserve a payload-free terminal receipt before granting a fresh retry budget.
-- The job identity and payload stay unchanged, including enqueue idempotency.
with candidates as materialized (
    select job_id,attempt_count,max_attempts,last_error_code,last_error_detail,updated_at,
           case when last_error_code='UniqueViolation' then 'canonical_identity_repaired'
                else 'agent_source_lookup_repaired' end as reason
    from public.semantic_processing_outbox job
    where status='quarantined' and job_kind='normalize_event'
      and semantic_contract_version=1 and processor_id='semantic-shadow'
      and processor_version='1.4+identity-1.0'
      and attempt_count>=max_attempts
      and source_identity_json->>'id'=source_event_id::text
      and source_identity_json->>'normalized_hash' ~ '^[0-9a-f]{64}$'
      and (
          (last_error_code='UniqueViolation' and last_error_detail ~
              '(^|[^[:alnum:]_])canonical_actions_pkey([^[:alnum:]_]|$)')
          or (last_error_code='KeyError' and last_error_detail in (
              format('published archive block not found for event %s',source_event_id),
              quote_literal(format('published archive block not found for event %s',source_event_id))
          ))
      )
      and not exists (
          select 1 from public.semantic_control_audit audit
          where audit.action='semantic_quarantine_requeue_v216' and audit.target=job.job_id::text
      )
    for update
), requeued as (
    update public.semantic_processing_outbox job
    set status='queued',attempt_count=0,available_at=now(),
        lease_token=null,lease_until=null,heartbeat_at=null,completed_at=null,
        last_error_code=null,last_error_detail=null,updated_at=now()
    from candidates old where job.job_id=old.job_id
    returning job.job_id
)
insert into public.semantic_control_audit(action,target,actor,details)
select 'semantic_quarantine_requeue_v216',old.job_id::text,'migration:216',
       jsonb_build_object(
           'outcome','requeued','reason',old.reason,
           'original_attempt_count',old.attempt_count,'original_max_attempts',old.max_attempts,
           'original_error_code',old.last_error_code,
           'original_error_detail_sha256',encode(sha256(convert_to(old.last_error_detail,'UTF8')),'hex'),
           'original_quarantined_at',old.updated_at
       )
from candidates old join requeued using(job_id);

insert into public.schema_migrations(version,name) values(216,'semantic_quarantine_requeue');
commit;
