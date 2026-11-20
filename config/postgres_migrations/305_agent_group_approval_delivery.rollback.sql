-- Explicit rollback refuses to discard a delivery audit or a later migration.
begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_agent_group_delivery_v305'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=305 and name='agent_group_approval_delivery')
       or exists(select 1 from public.schema_migrations where version>305) then
        raise exception 'agent_group_delivery_rollback_preflight' using errcode='55000';
    end if;
    if (select relowner from pg_catalog.pg_class where oid='public.sli_agent_audit'::regclass)
         is distinct from 'adlog_storage_owner'::regrole
       or (select relowner from pg_catalog.pg_class where oid='public.sli_agent_group_delivery_restore_v305'::regclass)
         is distinct from 'adlog_storage_owner'::regrole then
        raise exception 'agent_group_delivery_rollback_contract_invalid' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
lock table public.sli_agent_audit,public.sli_agent_group_delivery_restore_v305 in access exclusive mode;
do $$ declare saved record; begin
    select * into strict saved from public.sli_agent_group_delivery_restore_v305 where singleton;
    if (select pg_get_constraintdef(oid) from pg_catalog.pg_constraint
        where conrelid='public.sli_agent_audit'::regclass and conname='sli_agent_audit_action_check')
        is distinct from saved.installed_definition
       or (select obj_description(oid,'pg_constraint') from pg_catalog.pg_constraint
        where conrelid='public.sli_agent_audit'::regclass and conname='sli_agent_audit_action_check')
        is distinct from saved.installed_comment
       or exists(select 1 from public.sli_agent_audit where action='group_approval_delivery') then
        raise exception 'agent_group_delivery_rollback_state_exists' using errcode='55000';
    end if;
    alter table public.sli_agent_audit drop constraint sli_agent_audit_action_check;
    execute format('alter table public.sli_agent_audit add constraint sli_agent_audit_action_check %s',saved.prior_definition);
    execute format('comment on constraint sli_agent_audit_action_check on public.sli_agent_audit is %L',saved.prior_comment);
end $$;
drop table public.sli_agent_group_delivery_restore_v305;
delete from public.schema_migrations where version=305 and name='agent_group_approval_delivery';
reset role;
commit;
