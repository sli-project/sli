begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_native_radius_accounting_admission406'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations
                     where version=405 and name='file_permissions_opt_in')
       or exists(select 1 from public.schema_migrations where version>=406) then
        raise exception 'native_radius_accounting_admission406_preflight' using errcode='55000';
    end if;
end $$;
grant create on schema public to adlog_plugin_lifecycle_owner;
set local role adlog_plugin_lifecycle_owner;
create function public.radius_accounting_plugin_ready406() returns boolean
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select exists(select 1 from public.read_plugin_states_v1() s
        where s.plugin_id='sli.remote-access' and s.installed and s.configured and s.enabled
          and s.component_runtime='running')
$$;
revoke all on function public.radius_accounting_plugin_ready406() from public;
grant execute on function public.radius_accounting_plugin_ready406() to adlog_storage_owner;
reset role;
revoke create on schema public from adlog_plugin_lifecycle_owner;

set local role adlog_storage_owner;
create function public.radius_accounting_source_ready406(p_source text,p_subscription text,p_binding text,p_endpoint text,p_active boolean)
returns boolean language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select (p_active is false or public.radius_accounting_plugin_ready406())
       and exists (
        select 1 from pg_catalog.pg_roles r
        join pg_catalog.pg_auth_members m on m.member=r.oid
        join pg_catalog.pg_roles worker on worker.oid=m.roleid
        where r.rolname='sli_radius_accounting_login' and r.rolcanlogin and not r.rolinherit
          and not r.rolsuper and not r.rolcreatedb and not r.rolcreaterole and not r.rolreplication and not r.rolbypassrls
          and worker.rolname='adlog_nps_agent_import_worker' and m.set_option and not m.inherit_option and not m.admin_option
          and not exists(select 1 from pg_catalog.pg_auth_members extra where extra.member=r.oid and extra.roleid<>m.roleid)
          and pg_catalog.has_database_privilege(r.oid,current_database(),'CONNECT'))
       and exists (
        select 1 from public.acquisition_consumer_subscriptions sub
        join public.acquisition_stream_cursors c using(source_instance_id,stream_id,transport_binding)
        join public.acquisition_source_instances src using(source_instance_id)
        where sub.subscription_id=p_subscription and c.source_instance_id=p_source
          and c.stream_id='radius-accounting' and c.transport_binding=p_binding
          and src.source_kind='windows.nps.radius'
          and src.endpoint_identity=p_endpoint
          and src.adapter_binding='radius-accounting-database-compatible-v1'
          and sub.consumer_id='sli.windows.vpn-radius'
          and sub.consumer_component_id='radius-session-observation'
          and sub.routing_contract_id='sli.radius-accounting-runtime.v1'
          and sub.authority_mode='authoritative'
          and src.desired_activation='manual_enabled' and sub.desired_activation='manual_enabled')
$$;
revoke all on function public.radius_accounting_source_ready406(text,text,text,text,boolean) from public;
grant execute on function public.radius_accounting_source_ready406(text,text,text,text,boolean) to adlog_user,adlog_nps_agent_import_worker;
insert into public.schema_migrations(version,name) values(406,'native_radius_accounting_admission');
reset role;
commit;
