begin;
select pg_advisory_xact_lock(hashtext('sli_disabled_module_intake380'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=376 and name='workstation_import_isolation')
       or exists(select 1 from public.schema_migrations where version>=380) then
        raise exception 'disabled_module_intake380_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

-- Expose only module admission, without granting access to the lifecycle registry.
create function public.agent_module_enabled_v380(p_module text) returns boolean
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select case
      -- Beta excludes these collectors even if an old registration is still enabled.
      -- AD/DC, GPO, snapshots and heartbeat are core: never tied to plugin state.
      when p_module in ('sli.file-audit','sli.workstations','sli.vpn-nps','sli.radius-accounting') then false
      else true end
$$;
revoke all on function public.agent_module_enabled_v380(text) from public;
grant execute on function public.agent_module_enabled_v380(text) to adlog_user;

alter table public.sli_agent_packet_inbox drop constraint sli_agent_inbox_disabled363;
alter table public.sli_agent_packet_inbox add constraint sli_agent_inbox_disabled363
    check (module_disabled_at is null or imported_at is null);

-- Keep the bodies under the existing retention and evidence-hold rules.
update public.sli_agent_packet_inbox i set module_disabled_at=clock_timestamp()
where i.imported_at is null and i.module_disabled_at is null
  and (not public.agent_module_enabled_v380(i.envelope->>'module_id')
    or exists(select 1 from public.sli_agents a cross join lateral jsonb_array_elements(a.assigned_modules) m
      where a.id::text=i.envelope->>'agent_id' and m->>'module_id'=i.envelope->>'module_id'
        and m->'enabled'='false'::jsonb));

insert into public.schema_migrations(version,name) values(380,'disabled_module_intake');
reset role;
commit;
