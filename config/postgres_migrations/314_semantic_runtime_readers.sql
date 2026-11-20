-- T109 can read exactly one setting, without access to the settings table.
begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_semantic_runtime_readers_v314'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not pg_has_role(session_user,'adlog_user','MEMBER')
       or not has_column_privilege('adlog_user','public.platform_settings','key','SELECT')
       or not has_column_privilege('adlog_user','public.platform_settings','value','SELECT')
       or not exists(select 1 from public.schema_migrations where version=312 and name='semantic_workstation_discovery')
       or exists(select 1 from public.schema_migrations where version>=314)
       or (select proowner from pg_proc where oid='public.read_t109_policy()'::regprocedure)
          is distinct from 'adlog_storage_owner'::regrole then
        raise exception 'semantic_runtime_314_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
create view public.semantic_t109_setting_v314 with (security_barrier=true) as
    select value from public.platform_settings where key='security.t109.policy';
revoke all on public.semantic_t109_setting_v314 from public,adlog_user,adlog_semantic_worker;
-- The table's existing reader owns this fixed projection. No table GRANT is added.
reset role;
alter view public.semantic_t109_setting_v314 owner to adlog_user;
grant select on public.semantic_t109_setting_v314 to adlog_storage_owner;
set local role adlog_storage_owner;
do $patch$
declare definition text;
begin
    select pg_get_functiondef('public.read_t109_policy()'::regprocedure) into definition;
    if strpos(definition,'from public.platform_settings where key=''security.t109.policy''')=0 then
        raise exception 'semantic_runtime_314_policy_shape' using errcode='55000';
    end if;
    execute replace(definition,'from public.platform_settings where key=''security.t109.policy''',
        'from public.semantic_t109_setting_v314');
end $patch$;

-- Admission probe only: existing native binding/identity validation is retained.
-- Missing domain configuration is not a producer attempt or a healthy result.
create function public.password_source_ready_v314(s jsonb) returns boolean
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare b public.finding_evidence_source_bindings%rowtype; configured boolean;
begin
    b:=public.password_v2_source_binding(s);
    select m.password_detection_domain_id is not null into configured
        from public.sli_agent_module_bindings m where m.agent_id=b.agent_id and m.module_id='sli.windows.ad-dc';
    if not found then raise exception 'password_policy_source_unavailable' using errcode='42501'; end if;
    return configured;
end $$;
revoke all on function public.password_source_ready_v314(jsonb) from public,adlog_user;
grant execute on function public.password_source_ready_v314(jsonb) to adlog_semantic_worker;
insert into public.schema_migrations(version,name) values(314,'semantic_runtime_readers');
reset role;
commit;
