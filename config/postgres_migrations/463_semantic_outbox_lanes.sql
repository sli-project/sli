select pg_advisory_lock(hashtext('sli_semantic_outbox_lanes463'));
begin;
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=462 and name='file_actions_and_problems')
       or exists(select 1 from public.schema_migrations where version>=463) then
        raise exception 'semantic_outbox_lanes463_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
commit;

set role adlog_storage_owner;
-- Rebuild an invalid index shell left by a failed concurrent attempt.
drop index concurrently if exists public.semantic_outbox_lane_claim463;
create index concurrently semantic_outbox_lane_claim463 on public.semantic_processing_outbox
    ((case when job_kind='semantic_replay' then split_part(processor_version,'+r7-',1) else processor_version end),
     (case when job_kind in ('normalize_event','investigation_context') and payload_json->>'queue_lane'='live' then 1 else 0 end),
     available_at,created_at,job_id)
    where semantic_contract_version=1 and processor_id='semantic-shadow'
      and status in ('queued','failed','leased') and (attempt_count<max_attempts or status='leased')
      and job_kind<>'semantic_v2_quarantine_repair';

drop index concurrently if exists public.semantic_outbox_lane_age463;
create index concurrently semantic_outbox_lane_age463 on public.semantic_processing_outbox
    ((case when job_kind='semantic_replay' then split_part(processor_version,'+r7-',1) else processor_version end),
     (case when job_kind in ('normalize_event','investigation_context') and payload_json->>'queue_lane'='live' then 1 else 0 end),created_at)
    where semantic_contract_version=1 and processor_id='semantic-shadow'
      and status in ('queued','failed','leased') and (attempt_count<max_attempts or status='leased')
      and job_kind<>'semantic_v2_quarantine_repair';
reset role;

begin;
set local role adlog_storage_owner;
insert into public.schema_migrations(version,name) values(463,'semantic_outbox_lanes');
commit;
select pg_advisory_unlock(hashtext('sli_semantic_outbox_lanes463'));
