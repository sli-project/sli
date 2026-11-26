begin;
select pg_advisory_xact_lock(hashtext('sli_semantic_outbox_retention426'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=421 and name='sli_own_actions')
       or exists(select 1 from public.schema_migrations where version>=426) then
        raise exception 'semantic_outbox_retention426_preflight' using errcode='55000';
    end if;
end $$;
set local lock_timeout='5s';
set local role adlog_storage_owner;

create index semantic_outbox_completed426 on public.semantic_processing_outbox
    (job_id, greatest(created_at,updated_at,completed_at)) where status='completed';
alter table public.semantic_processing_outbox
    set (autovacuum_vacuum_scale_factor=0.02, autovacuum_vacuum_threshold=1000);

insert into public.schema_migrations(version,name) values(426,'semantic_outbox_retention');
reset role;
commit;
