begin;
select pg_advisory_xact_lock(hashtext('sli_home_read_indexes424'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations
           where version=424 and name='home_read_indexes')
       or exists(select 1 from public.schema_migrations where version>424) then
        raise exception 'home_read_indexes424_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

drop function public.home_published_findings424(bigint[]);
drop index public.finding_event_copy_subject424;
drop index public.finding_event_copy_identity424;
drop index public.event_hot_home_changes424;
delete from public.schema_migrations where version=424 and name='home_read_indexes';
commit;
