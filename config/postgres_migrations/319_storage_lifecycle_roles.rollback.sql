begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_storage_lifecycle_roles_v319'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=318 and name='semantic_pending_candidates')
       or not exists(select 1 from public.schema_migrations where version=319 and name='storage_lifecycle_roles')
       or exists(select 1 from public.schema_migrations where version>319) then
        raise exception 'storage_lifecycle_319_rollback_preflight' using errcode='55000';
    end if;
end $$;
do $patch$ declare definition text; begin
    definition:=pg_get_functiondef('public.ad_snapshot_history_confirmation_guard_v165()'::regprocedure);
    if strpos(definition,$new$if tg_op='DELETE' and ((current_user='postgres' and session_user='adlog_user') or (current_user='adlog_storage_lifecycle_guard' and pg_has_role(session_user,'adlog_storage_lifecycle_delete','MEMBER'))) then$new$)=0 then raise exception 'storage_lifecycle_319_guard_shape'; end if;
    execute replace(definition,$new$if tg_op='DELETE' and ((current_user='postgres' and session_user='adlog_user') or (current_user='adlog_storage_lifecycle_guard' and pg_has_role(session_user,'adlog_storage_lifecycle_delete','MEMBER'))) then$new$,$old$if tg_op='DELETE' and current_user='postgres' and session_user='adlog_user' then$old$);
end $patch$;
drop function public.lock_storage_lifecycle_tables_v319(text);
drop function public.lock_storage_lifecycle_events_v319(bigint[]);
drop function public.lock_storage_lifecycle_facts_v319(bigint[]);
drop function public.lock_storage_lifecycle_semantic_v319(bigint[]);
drop function public.lock_storage_lifecycle_packets_v319(timestamptz,integer);
drop function public.lock_storage_lifecycle_snapshots_v319(timestamptz);
drop function public.expire_storage_lifecycle_confirmations_v319(timestamptz);
drop view public.storage_lifecycle_setting_v319;
-- Include column ACLs (worker SELECT and guard UPDATE), which a table-level
-- REVOKE ALL does not remove. DROP OWNED also removes local default ACLs.
-- Like migration 287, preserve roles and memberships used by another database.
do $$ declare role_name text; role_id oid;
begin
    foreach role_name in array array['adlog_storage_lifecycle_delete','adlog_storage_lifecycle_worker','adlog_storage_lifecycle_guard'] loop
        select oid into strict role_id from pg_roles where rolname=role_name;
        execute format('drop owned by %I',role_name);
        if not exists(select 1 from pg_shdepend where refclassid='pg_authid'::regclass
            and refobjid=role_id and dbid<>0
            and dbid<>(select oid from pg_database where datname=current_database())) then
            execute format('drop role %I',role_name);
        end if;
    end loop;
end $$;
set local role adlog_storage_owner;
delete from public.schema_migrations where version=319 and name='storage_lifecycle_roles';
reset role;
commit;
