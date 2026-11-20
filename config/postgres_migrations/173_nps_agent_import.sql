-- Dedicated opt-in Accounting inbox importer. No HTTP/agent role escalation.
begin;
select pg_advisory_xact_lock(hashtext('sli_nps_agent_import_v173'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 173 requires membership in adlog_storage_owner';
    end if;
    if exists(select 1 from public.schema_migrations where version>=173) then
        raise exception 'migration 173 already applied or out of order';
    end if;
    if not exists(select 1 from public.schema_migrations where version=172 and name='agent_ad_snapshot_import') then
        raise exception 'migration 173 requires exact migration 172 agent_ad_snapshot_import';
    end if;
    if not exists(select 1 from pg_roles where rolname='adlog_nps_agent_import_worker') then
        create role adlog_nps_agent_import_worker nologin noinherit nosuperuser
            nocreatedb nocreaterole noreplication nobypassrls;
    else
        raise exception 'migration 173 worker role already exists';
    end if;
end $$;
grant adlog_nps_agent_import_worker to adlog_storage_owner;
grant adlog_radius_accounting_worker to adlog_nps_agent_import_worker;
grant usage on schema public to adlog_nps_agent_import_worker;
grant select on public.sli_agents,public.sli_agent_receipts,public.sli_agent_packet_inbox
    to adlog_nps_agent_import_worker;
grant update(imported_at) on public.sli_agent_packet_inbox to adlog_nps_agent_import_worker;
grant execute on function public.read_plugin_states_v1() to adlog_nps_agent_import_worker;
set local role adlog_storage_owner;
insert into public.schema_migrations(version,name) values(173,'nps_agent_import');
commit;
