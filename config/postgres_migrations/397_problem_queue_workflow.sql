begin;
select pg_advisory_xact_lock(hashtext('sli_problem_queue_workflow397'));
do $$ begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER')
       or not exists(select 1 from public.schema_migrations where version=395 and name='problem_account_identity')
       or exists(select 1 from public.schema_migrations where version>=397)
       or not exists(select 1 from public.report_registry_v4 r join public.report_datasets_v4 d on d.id=r.dataset_id
           where r.report_key='security.queue' and r.status='published' and d.dataset_key='security.problems'
             and r.definition_json->>'export_policy'='disabled' and not (d.actions_json ? 'export')
             and not (r.definition_json->'actions' ? 'export')) then
        raise exception 'problem_queue_workflow397_preflight' using errcode='55000';
    end if;
end $$;

set local role adlog_storage_owner;

create table public.finding_queue_deferrals (
    finding_id bigint primary key references public.findings(id) on delete cascade,
    until_at timestamptz not null
);
grant select, insert, update, delete on public.finding_queue_deferrals to adlog_user;

-- Publish the new action through the existing export capability and report grants.
reset role;
update public.report_datasets_v4 d set actions_json=d.actions_json || jsonb_build_array('export')
where d.id in (select dataset_id from public.report_registry_v4 where report_key='security.queue' and status='published');
update public.report_registry_v4 set definition_json=definition_json || jsonb_build_object(
    'actions',definition_json->'actions' || jsonb_build_array('export'), 'export_policy','controlled')
where report_key='security.queue' and status='published';

insert into public.schema_migrations(version,name) values (397,'problem_queue_workflow');
commit;
