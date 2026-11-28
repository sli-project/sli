begin;
select pg_advisory_xact_lock(hashtext('sli_file_action_groups465'));
set local role adlog_storage_owner;
drop function public.file_mass_problem_links465(jsonb);
drop function public.file_action_group_page465(jsonb,text,timestamptz,timestamptz,text,boolean,text,text,jsonb,integer);
delete from public.schema_migrations where version=465 and name='file_action_groups';
commit;
