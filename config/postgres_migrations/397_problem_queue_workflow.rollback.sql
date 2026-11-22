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
update public.report_datasets_v4 d set actions_json=d.actions_json - 'export'
where d.id in (select dataset_id from public.report_registry_v4 where report_key='security.queue' and status='published');
update public.report_registry_v4 set definition_json=definition_json || jsonb_build_object(
    'actions',(definition_json->'actions') - 'export', 'export_policy','disabled')
where report_key='security.queue' and status='published';
delete from public.schema_migrations where version=397 and name='problem_queue_workflow';
commit;
