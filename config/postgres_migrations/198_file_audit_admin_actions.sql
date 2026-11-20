-- Admit the existing audited file-audit commands without changing prior actions.
begin;
select pg_advisory_xact_lock(hashtext('sli_file_audit_admin_actions_v198'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 198 requires membership in adlog_storage_owner';
    end if;
    if not exists(select 1 from public.schema_migrations where version=197 and name='workstation_file_audit')
       or exists(select 1 from public.schema_migrations where version>=198) then
        raise exception 'migration 198 requires exact migration 197 workstation_file_audit and unused version 198';
    end if;
end $$;
set local role adlog_storage_owner;
do $$
declare previous text;
begin
    select pg_get_expr(conbin,conrelid) into strict previous from pg_constraint
    where conrelid='public.sli_agent_audit'::regclass and conname='sli_agent_audit_action_check' and contype='c';
    alter table public.sli_agent_audit drop constraint sli_agent_audit_action_check;
    execute format('alter table public.sli_agent_audit add constraint sli_agent_audit_action_check check ((%s) or action in (''file_audit_command'',''local_file_audit_command''))',previous);
end $$;
reset role;
insert into public.schema_migrations(version,name) values(198,'file_audit_admin_actions');
commit;
