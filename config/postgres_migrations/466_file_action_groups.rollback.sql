begin;
select pg_advisory_xact_lock(hashtext('sli_file_action_groups466'));
set local role adlog_storage_owner;
drop function public.file_mass_problem_links466(jsonb);
drop function public.file_action_group_page466(jsonb,text,timestamptz,timestamptz,text,boolean,text,text,jsonb,integer);
delete from public.schema_migrations where version=466 and name='file_action_groups';
commit;
