begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_semantic_runtime_readers_v314'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not pg_has_role(session_user,'adlog_user','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=314 and name='semantic_runtime_readers')
       or exists(select 1 from public.schema_migrations where version>314)
       or (select proowner from pg_catalog.pg_proc where oid='public.read_t109_policy()'::regprocedure)
          is distinct from 'adlog_storage_owner'::regrole
       or (select proowner from pg_catalog.pg_proc where oid='public.password_source_ready_v314(jsonb)'::regprocedure)
          is distinct from 'adlog_storage_owner'::regrole
       or (select relowner from pg_catalog.pg_class where oid='public.semantic_t109_setting_v314'::regclass)
          is distinct from 'adlog_user'::regrole then
        raise exception 'semantic_runtime_314_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
do $patch$
declare definition text;
begin
    select pg_get_functiondef('public.read_t109_policy()'::regprocedure) into definition;
    if strpos(definition,'from public.semantic_t109_setting_v314')=0 then
        raise exception 'semantic_runtime_314_policy_shape' using errcode='55000';
    end if;
    execute replace(definition,'from public.semantic_t109_setting_v314',
        'from public.platform_settings where key=''security.t109.policy''');
end $patch$;
drop function public.password_source_ready_v314(jsonb);
reset role;
drop view public.semantic_t109_setting_v314;
set local role adlog_storage_owner;
delete from public.schema_migrations where version=314 and name='semantic_runtime_readers';
reset role;
commit;
