-- Exact configured agent slots and terminal receipts for superseded snapshots.
begin;
select pg_advisory_xact_lock(hashtext('sli_agent_snapshot_publication_health_v189'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 189 requires storage owner membership';
    end if;
    if not exists(select 1 from public.schema_migrations where version=188 and name='agent_group_deployment')
       or not exists(select 1 from public.schema_migrations where version=128 and name='ad_snapshot_v2_schedule')
       or not exists(select 1 from public.schema_migrations where version=174 and name='agent_gpo_snapshot_import')
       or exists(select 1 from public.schema_migrations where version>=189) then
        raise exception 'migration 189 requires exact predecessors and unused version 189';
    end if;
end $$;

-- Preserve v1/v2 semantics. v3 is an exact UTC receipt of the slot already
-- validated against the signed agent policy, including fractional-hour zones.
alter table public.ad_snapshot_manifests
    drop constraint ad_snapshot_manifests_contract_version_check,
    drop constraint ad_snapshot_manifests_slot_start_utc_check;
alter table public.ad_snapshot_manifests
    add constraint ad_snapshot_manifests_contract_version_check check(contract_version in (
        'sli.ad-snapshot-manifest/1.0', 'sli.ad-snapshot-manifest/2.0', 'sli.ad-snapshot-manifest/3.0')),
    add constraint ad_snapshot_manifests_slot_start_utc_check check(
        (contract_version='sli.ad-snapshot-manifest/1.0'
            and schedule_timezone is null and scheduled_local_at is null
            and ((slot_start_utc at time zone 'UTC')=date_trunc('day',slot_start_utc at time zone 'UTC')
                or (slot_start_utc at time zone 'UTC')=date_trunc('day',slot_start_utc at time zone 'UTC')+interval '12 hours'))
        or (contract_version='sli.ad-snapshot-manifest/2.0'
            and schedule_timezone='Asia/Novosibirsk' and scheduled_local_at is not null
            and scheduled_local_at=date_trunc('minute',scheduled_local_at)
            and scheduled_local_at::time in (time '06:00:00',time '18:00:00')
            and slot_start_utc=scheduled_local_at at time zone 'Asia/Novosibirsk')
        or (contract_version='sli.ad-snapshot-manifest/3.0'
            and schedule_timezone is not null and schedule_timezone='UTC' and scheduled_local_at is not null
            and scheduled_local_at=date_trunc('minute',scheduled_local_at)
            and slot_start_utc=scheduled_local_at at time zone 'UTC')
    );

create function public.ad_snapshot_manifest_apply_agent_schedule_header()
returns trigger language plpgsql as $$
declare
    expected_local_at timestamp without time zone := new.slot_start_utc at time zone 'UTC';
begin
    if new.schedule_timezone is not null and new.schedule_timezone<>'UTC'
       or new.scheduled_local_at is not null and new.scheduled_local_at is distinct from expected_local_at then
        raise exception 'v3 AD snapshot schedule header must match the exact UTC slot';
    end if;
    new.schedule_timezone := 'UTC';
    new.scheduled_local_at := expected_local_at;
    return new;
end $$;
create trigger trg_ad_snapshot_manifests_agent_schedule_header
    before insert on public.ad_snapshot_manifests for each row
    when (new.contract_version='sli.ad-snapshot-manifest/3.0')
    execute function public.ad_snapshot_manifest_apply_agent_schedule_header();

set local role adlog_storage_owner;
alter table public.sli_agent_snapshot_cycles
    drop constraint sli_agent_snapshot_cycles_publication_state_check,
    drop constraint sli_agent_snapshot_publication_consistent,
    add column superseded_reason text,
    add column superseded_at timestamptz;
alter table public.sli_agent_snapshot_cycles
    add constraint sli_agent_snapshot_cycles_publication_state_check
        check(publication_state in ('pending','published','superseded')),
    add constraint sli_agent_snapshot_publication_consistent check(
        (publication_state='pending' and manifest_id is null and gpo_source_run_id is null
            and published_at is null and superseded_reason is null and superseded_at is null)
        or (publication_state='published' and published_at is not null and transport_state='complete'
            and superseded_reason is null and superseded_at is null and (
                (module_id='sli.ad-snapshot' and manifest_id is not null and gpo_source_run_id is null)
                or (module_id='sli.gpo-snapshot' and gpo_source_run_id is not null and manifest_id is null)))
        or (publication_state='superseded' and transport_state='complete' and manifest_id is null
            and gpo_source_run_id is null and published_at is null and superseded_at is not null
            and superseded_reason is not null and (
                (module_id='sli.ad-snapshot' and superseded_reason='agent_ad_snapshot_superseded')
                or (module_id='sli.gpo-snapshot' and superseded_reason='agent_gpo_snapshot_superseded')))
    );
grant update(superseded_reason,superseded_at) on public.sli_agent_snapshot_cycles to adlog_context_worker;
reset role;
insert into public.schema_migrations(version,name) values(189,'agent_snapshot_publication_health');
commit;
