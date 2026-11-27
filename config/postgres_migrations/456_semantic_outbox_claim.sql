select pg_advisory_lock(hashtext('sli_semantic_outbox_claim456'));
begin;
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=455 and name='account_detection_pending')
       or exists(select 1 from public.schema_migrations where version>=456) then
        raise exception 'semantic_outbox_claim456_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
commit;

set role adlog_storage_owner;
-- Retry an interrupted concurrent build, including an invalid index shell.
drop index concurrently if exists public.semantic_outbox_claim456;
create index concurrently semantic_outbox_claim456 on public.semantic_processing_outbox
    ((case when job_kind='semantic_replay' then split_part(processor_version,'+r7-',1) else processor_version end),
     available_at,created_at,job_id)
    where semantic_contract_version=1 and processor_id='semantic-shadow'
      and status in ('queued','failed','leased') and (attempt_count<max_attempts or status='leased');
reset role;

begin;
set local role adlog_storage_owner;
insert into public.schema_migrations(version,name) values(456,'semantic_outbox_claim');
commit;
select pg_advisory_unlock(hashtext('sli_semantic_outbox_claim456'));
