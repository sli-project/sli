-- Register file-event classification and isolate immutable packet conflicts.
begin;
select pg_advisory_xact_lock(hashtext('sli_agent_packet_projection_recovery_v207'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=206 and name='file_audit_catalog_revision')
       or exists(select 1 from public.schema_migrations where version>=207) then
        raise exception 'migration 207 prerequisites failed';
    end if;
end $$;
set local role adlog_storage_owner;

-- Exact version emitted by config/file_audit_event_catalog.json. Retain all
-- previously registered revisions and leave the enforcing trigger unchanged.
insert into public.event_catalog_revisions(version) values('1.0.0')
on conflict(version) do nothing;

create table public.sli_agent_packet_quarantine (
    packet_id uuid primary key references public.sli_agent_packet_inbox(packet_id),
    reason_code text not null check(reason_code in (
        'source_event_allocation_hash_mismatch','published_source_event_hash_mismatch')),
    event_ordinal integer not null check(event_ordinal>=0),
    quarantined_at timestamptz not null default clock_timestamp()
);
revoke all on public.sli_agent_packet_quarantine from public,adlog_user,adlog_nps_agent_import_worker;
grant select,insert on public.sli_agent_packet_quarantine to adlog_user;
grant select on public.sli_agent_packet_quarantine to adlog_nps_agent_import_worker;

insert into public.schema_migrations(version,name) values(207,'agent_packet_projection_recovery');
commit;
