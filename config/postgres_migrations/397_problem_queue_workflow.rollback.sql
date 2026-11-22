begin;
select pg_advisory_xact_lock(hashtext('sli_problem_queue_workflow397'));
do $$ begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER')
       or not exists(select 1 from public.schema_migrations where version=397 and name='problem_queue_workflow')
       or exists(select 1 from public.schema_migrations where version>397) then
        raise exception 'problem_queue_workflow397_rollback_preflight' using errcode='55000';
    end if;
end $$;

set local role adlog_storage_owner;
drop table public.finding_queue_deferrals;
reset role;
delete from public.schema_migrations where version=397 and name='problem_queue_workflow';
commit;
