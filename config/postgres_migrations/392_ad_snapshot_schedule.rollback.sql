begin;
select pg_advisory_xact_lock(hashtext('sli_ad_snapshot_schedule392'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=392 and name='ad_snapshot_schedule')
       or exists(select 1 from public.schema_migrations where version>392) then
        raise exception 'ad_snapshot_schedule392_rollback_preflight' using errcode='55000';
    end if;
end $$;

reset role;
create or replace function public.ad_snapshot_manifest_apply_v2_schedule_header()
returns trigger language plpgsql as $$
declare
    expected_local_at timestamp without time zone;
begin
    if new.contract_version='sli.ad-snapshot-manifest/2.0' then
        expected_local_at := new.slot_start_utc at time zone 'Asia/Novosibirsk';
        new.schedule_timezone := coalesce(new.schedule_timezone,'Asia/Novosibirsk');
        if new.schedule_timezone<>'Asia/Novosibirsk' then
            raise exception 'v2 AD snapshot manifests require Asia/Novosibirsk schedule_timezone';
        end if;
        if new.scheduled_local_at is null then
            new.scheduled_local_at := expected_local_at;
        elsif new.scheduled_local_at is distinct from expected_local_at then
            raise exception 'v2 AD snapshot scheduled_local_at must match slot_start_utc';
        end if;
    elsif new.contract_version='sli.ad-snapshot-manifest/1.0' then
        if new.schedule_timezone is not null or new.scheduled_local_at is not null then
            raise exception 'v1 AD snapshot manifests cannot declare a schedule header';
        end if;
    end if;
    return new;
end $$;

alter table public.ad_snapshot_manifests drop constraint ad_snapshot_manifests_slot_start_utc_check;
-- Keep published manifests and their immutable hashes, including other zones.
alter table public.ad_snapshot_manifests add constraint ad_snapshot_manifests_slot_start_utc_check check (
    (contract_version='sli.ad-snapshot-manifest/1.0' and schedule_timezone is null and scheduled_local_at is null
        and (slot_start_utc at time zone 'UTC')::time in (time '00:00',time '12:00'))
    or (contract_version='sli.ad-snapshot-manifest/2.0' and schedule_timezone='Asia/Novosibirsk' and scheduled_local_at is not null
        and scheduled_local_at::time in (time '06:00',time '18:00')
        and slot_start_utc=scheduled_local_at at time zone 'Asia/Novosibirsk')
    or (contract_version='sli.ad-snapshot-manifest/3.0' and schedule_timezone is not null and schedule_timezone='UTC'
        and scheduled_local_at is not null and scheduled_local_at=date_trunc('minute',scheduled_local_at)
        and slot_start_utc=scheduled_local_at at time zone 'UTC')
) not valid;

set local role adlog_storage_owner;
alter table public.sli_agent_snapshot_bindings drop column follow_server_timezone;
delete from public.schema_migrations where version=392 and name='ad_snapshot_schedule';
reset role;
commit;
