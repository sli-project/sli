-- Plugin-owned GPO publication. No collector, binding or schedule is enabled.
begin;
select pg_advisory_xact_lock(hashtext('sli_agent_gpo_snapshot_import_v174'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 174 requires membership in adlog_storage_owner';
    end if;
    -- 173 belongs to the independent PR; do not synthesize its marker.
    if not exists(select 1 from public.schema_migrations where version=172 and name='agent_ad_snapshot_import')
       or exists(select 1 from public.schema_migrations where version>=174) then
        raise exception 'migration 174 requires exact migration 172 agent_ad_snapshot_import';
    end if;
end $$;
grant references(run_id) on public.ad_context_runs to adlog_storage_owner;
set local role adlog_storage_owner;
alter table public.sli_agent_snapshot_cycles
    add column gpo_source_run_id uuid references public.ad_context_runs(run_id),
    drop constraint sli_agent_snapshot_publication_consistent;
alter table public.sli_agent_snapshot_cycles
    add constraint sli_agent_snapshot_publication_consistent check(
        (publication_state='pending' and manifest_id is null and gpo_source_run_id is null and published_at is null)
        or (publication_state='published' and published_at is not null and transport_state='complete' and (
            (module_id='sli.ad-snapshot' and manifest_id is not null and gpo_source_run_id is null)
            or (module_id='sli.gpo-snapshot' and gpo_source_run_id is not null and manifest_id is null)
        ))
    );
create index sli_agent_gpo_snapshot_publication_pending on public.sli_agent_snapshot_cycles(cycle_id)
    where module_id='sli.gpo-snapshot' and publication_state='pending';
grant update(gpo_source_run_id) on public.sli_agent_snapshot_cycles to adlog_context_worker;
reset role;
insert into public.schema_migrations(version,name) values(174,'agent_gpo_snapshot_import');
commit;
