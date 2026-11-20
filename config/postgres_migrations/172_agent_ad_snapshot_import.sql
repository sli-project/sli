-- AD publication by the existing trusted context worker. No collector enabled.
begin;
select pg_advisory_xact_lock(hashtext('sli_agent_ad_snapshot_import_v172'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 172 requires membership in adlog_storage_owner';
    end if;
    if not exists(select 1 from public.schema_migrations where version=171 and name='agent_windows_audit')
       or exists(select 1 from public.schema_migrations where version>=172) then
        raise exception 'migration 172 requires exact migration 171 agent_windows_audit';
    end if;
end $$;
grant references(manifest_id) on public.ad_snapshot_manifests to adlog_storage_owner;
set local role adlog_storage_owner;
alter table public.sli_agent_snapshot_cycles
    add column publication_state text not null default 'pending' check(publication_state in ('pending','published')),
    add column manifest_id uuid references public.ad_snapshot_manifests(manifest_id),
    add column published_at timestamptz,
    add constraint sli_agent_snapshot_publication_consistent check(
        (publication_state='pending' and manifest_id is null and published_at is null)
        or (publication_state='published' and manifest_id is not null and published_at is not null
            and module_id='sli.ad-snapshot' and transport_state='complete')
    );
create index sli_agent_ad_snapshot_publication_pending on public.sli_agent_snapshot_cycles(cycle_id)
    where module_id='sli.ad-snapshot' and publication_state='pending';
-- The consumer acquires lifecycle locks and imports on the same worker
-- connection. adlog_user receives no AD import privileges or role membership.
grant select on public.sli_agents,public.sli_agent_receipts,public.sli_agent_snapshot_cycles,
    public.sli_agent_snapshot_chunks to adlog_context_worker;
grant update(id) on public.sli_agents to adlog_context_worker; -- SELECT FOR UPDATE only
grant update(transport_state,completed_at,publication_state,manifest_id,published_at)
    on public.sli_agent_snapshot_cycles to adlog_context_worker;
reset role;
-- Legacy snapshots and the plugin state function retain their existing owners.
alter table public.computers_v6_source_snapshots
    drop constraint computers_v6_source_snapshots_collector_sha256_check;
alter table public.computers_v6_source_snapshots
    add constraint computers_v6_source_snapshots_collector_sha256_check check(
        octet_length(collector_sha256)=32 and (
        collector_sha256=decode('caf0ee7e590e133a4e834bb31997e5253a5e707e347e677158260ab7085154d5','hex')
        or (collector_version='sli-agent/ad-snapshot/1'
            and collector_sha256=sha256(convert_to('sli-agent/ad-snapshot/1','UTF8')))
        )
    );
grant execute on function public.read_plugin_states_v1() to adlog_context_worker;
grant select,insert on public.users_report_v2_snapshots,public.computers_v6_source_snapshots to adlog_context_worker;
grant usage,select on sequence public.users_report_v2_snapshots_snapshot_id_seq,
    public.computers_v6_source_snapshots_source_snapshot_id_seq to adlog_context_worker;
insert into public.schema_migrations(version,name) values(172,'agent_ad_snapshot_import');
commit;
