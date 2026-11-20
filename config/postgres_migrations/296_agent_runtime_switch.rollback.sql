-- Explicit operator rollback only. Refuse to discard any runtime handoff state.
begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_agent_runtime_switch_v296'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not pg_has_role('adlog_storage_owner','adlog_file_audit_owner','MEMBER') then
        raise exception 'agent_runtime_switch_rollback_preflight' using errcode='55000';
    end if;
    if not exists(select 1 from public.schema_migrations where version=296 and name='agent_runtime_switch')
       or exists(select 1 from public.schema_migrations where version>296) then
        raise exception 'agent_runtime_switch_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
lock table public.sli_agents,public.sli_agent_runtime_switches,public.sli_agent_audit
    in access exclusive mode;
do $$ begin
    if exists(select 1 from public.sli_agents where status='replaced') then
        raise exception 'agent_runtime_switch_rollback_replaced_agents' using errcode='55000';
    end if;
    if exists(select 1 from public.sli_agent_runtime_switches)
       or exists(select 1 from public.sli_agents where source_agent_id is not null
                 or source_host_id is not null or runtime_resume<>'{}'::jsonb)
       or exists(select 1 from public.sli_agent_audit
                 where action in ('runtime_switch_prepare','runtime_switch_complete')) then
        raise exception 'agent_runtime_switch_rollback_handoff_exists' using errcode='55000';
    end if;
    if not exists(select 1 from public.sli_agent_runtime_switch_restore_v296 where object_key='issuer')
       or not exists(select 1 from public.sli_agent_runtime_switch_restore_v296 where object_key='audit_constraint') then
        raise exception 'agent_runtime_switch_rollback_restore_missing' using errcode='55000';
    end if;
end $$;
-- CREATE OR REPLACE preserves each capability's owner, ACL and trigger linkage.
do $$ declare f record; prior text; begin
    for f in select *,has_schema_privilege(owner_name,schema_name,'CREATE') as had_create
        from public.sli_agent_runtime_switch_restore_v296 where object_key<>'audit_constraint' loop
        if not pg_has_role(session_user,f.owner_name,'MEMBER') then
            raise exception 'agent_runtime_switch_rollback_owner_membership' using errcode='42501';
        end if;
        if not f.had_create then
            reset role;
            execute format('grant create on schema %I to %I',f.schema_name,f.owner_name);
        end if;
        execute format('set local role %I',f.owner_name);
        execute f.definition;
        if not f.had_create then
            reset role;
            execute format('revoke create on schema %I from %I',f.schema_name,f.owner_name);
        end if;
        set local role adlog_storage_owner;
    end loop;
    select definition into strict prior from public.sli_agent_runtime_switch_restore_v296
        where object_key='audit_constraint';
    alter table public.sli_agent_audit drop constraint sli_agent_audit_action_check;
    execute format('alter table public.sli_agent_audit add constraint sli_agent_audit_action_check check (%s)',prior);
end $$;
drop function public.replace_agent_runtime_v296(uuid,uuid,text,text);
reset role;
set local role adlog_file_audit_owner;
drop function sli_plugin_file_audit.copy_runtime_v296(uuid,uuid,bigint);
reset role;
set local role adlog_storage_owner;
drop trigger agent_runtime_source_guard on public.sli_agents;
drop function public.agent_runtime_source_guard_v296();
drop function public.agent_current_runtime_v296(uuid);
drop function public.agent_source_identity_v296(uuid);
drop table public.sli_agent_runtime_switches;
drop index public.sli_agents_active_source_v296;
alter table public.sli_agent_enrollment_tokens drop column replacement_for,drop column enrolled_agent_id;
alter table public.sli_agents drop column source_host_id,drop column source_agent_id,drop column runtime_resume;
alter table public.sli_agents drop constraint sli_agents_status_check;
alter table public.sli_agents add constraint sli_agents_status_check check(status in ('active','disabled'));
drop table public.sli_agent_runtime_switch_restore_v296;
delete from public.schema_migrations where version=296 and name='agent_runtime_switch';
commit;
