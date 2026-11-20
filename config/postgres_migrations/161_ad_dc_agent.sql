-- AD/DC agent bindings. Assignment and collection remain opt-in.
begin;
select pg_advisory_xact_lock(hashtext('sli_ad_dc_agent_v161'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 161 requires membership in adlog_storage_owner';
    end if;
    if exists(select 1 from public.schema_migrations where version=161) then
        raise exception 'migration 161 already applied';
    end if;
    if not exists(select 1 from public.schema_migrations where version=160 and name='agent_workstation_dispatch')
       or exists(select 1 from public.schema_migrations where version>160) then
        raise exception 'migration 161 requires exact migration 160 agent_workstation_dispatch';
    end if;
end $$;
set local role adlog_storage_owner;
-- Owner-provisioned bindings remain read-only to runtime. No opt-in on upgrade.
alter table sli_agent_module_bindings drop constraint sli_agent_module_bindings_module_id_check;
alter table sli_agent_module_bindings add constraint sli_agent_module_bindings_module_id_check
    check (module_id in ('sli.windows-eventlog','sli.workstations','sli.windows.ad-dc'));
insert into public.schema_migrations(version,name) values(161,'ad_dc_agent');
commit;
