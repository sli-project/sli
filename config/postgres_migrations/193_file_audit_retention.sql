-- Stage 5: owner-managed holds and bounded core-owned retention privileges.
begin;
select pg_advisory_xact_lock(hashtext('sli_file_audit_retention_v193'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=192 and name='workstation_retention_jobs')
       or not exists(select 1 from public.schema_migrations where version=191 and name='file_audit_reports')
       or exists(select 1 from public.schema_migrations where version>=193) then
        raise exception 'migration 193 prerequisites failed';
    end if;
end $$;
set local role adlog_storage_owner;
grant references(packet_id) on public.sli_agent_packet_inbox to adlog_file_audit_owner;
grant references(packet_id) on public.sli_agent_receipts to adlog_file_audit_owner;
create index file_audit_inbox_retention on public.sli_agent_packet_inbox(received_at,packet_id)
    where envelope->>'module_id'='sli.file-audit' and imported_at is not null;
reset role;
set local role adlog_file_audit_owner;
grant usage on schema sli_plugin_file_audit to adlog_storage_owner;
create table sli_plugin_file_audit.payload_expirations (
    packet_id uuid primary key references public.sli_agent_receipts(packet_id),
    events jsonb not null check(jsonb_typeof(events)='array' and jsonb_array_length(events)<=256),
    expired_at timestamptz not null,
    source_payload_state text not null default 'expired' check(source_payload_state='expired')
);
create index file_audit_expired_event_lookup on sli_plugin_file_audit.payload_expirations using gin(events jsonb_path_ops);
revoke all on sli_plugin_file_audit.payload_expirations from public,adlog_user,adlog_file_audit_runtime;
grant select,insert on sli_plugin_file_audit.payload_expirations to adlog_storage_owner;
create table sli_plugin_file_audit.retention_holds (
    hold_id uuid primary key,
    packet_id uuid references public.sli_agent_packet_inbox(packet_id),
    snapshot_id uuid references sli_plugin_file_audit.access_snapshots(snapshot_id),
    reason_code text not null check(reason_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    created_at timestamptz not null default clock_timestamp(),
    check((packet_id is null)<>(snapshot_id is null))
);
create index file_audit_packet_holds on sli_plugin_file_audit.retention_holds(packet_id) where packet_id is not null;
create index file_audit_snapshot_holds on sli_plugin_file_audit.retention_holds(snapshot_id) where snapshot_id is not null;
create index file_audit_snapshot_retention on sli_plugin_file_audit.access_snapshots(observed_at,snapshot_id);
revoke all on sli_plugin_file_audit.retention_holds from public,adlog_user,adlog_file_audit_runtime;
grant select,insert,delete on sli_plugin_file_audit.retention_holds to adlog_storage_owner;
grant select,delete on sli_plugin_file_audit.access_snapshots to adlog_storage_owner;
grant update(snapshot_id) on sli_plugin_file_audit.access_snapshots to adlog_storage_owner;
grant select on sli_plugin_file_audit.rule_snapshots,sli_plugin_file_audit.collection_publications to adlog_storage_owner;
grant select on sli_plugin_file_audit.observations,sli_plugin_file_audit.action_evidence,
    sli_plugin_file_audit.rule_actions to adlog_storage_owner;
reset role;
-- The core lifecycle already owns the inbox; neither the application nor a
-- plugin worker receives destructive grants. Cleanup remains opt-in until
-- installed history/backup acceptance; no existing policy is switched on.
set local role adlog_storage_owner;
insert into public.schema_migrations(version,name) values(193,'file_audit_retention');
reset role;
commit;
