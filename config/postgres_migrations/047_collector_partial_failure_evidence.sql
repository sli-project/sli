begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_collector_partial_failure_evidence_v47'));

do $$
begin
    if not exists (
        select 1 from schema_migrations
        where version=46 and name='ad_context_snapshot_heartbeat'
    ) then
        raise exception 'migration 047 requires migration 046';
    end if;
    if to_regclass('collector_channel_runs') is null then
        raise exception 'migration 047 requires collector_channel_runs';
    end if;
end
$$;

alter table collector_channel_runs
    add column if not exists partial_kind text,
    add column if not exists failure_stage text,
    add column if not exists cursor_commit_allowed boolean;

insert into schema_migrations(version, name)
values (47, 'collector_partial_failure_evidence')
on conflict(version) do update set name=excluded.name, applied_at=now();

commit;
