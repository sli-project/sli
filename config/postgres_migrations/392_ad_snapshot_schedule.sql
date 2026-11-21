begin;
select pg_advisory_xact_lock(hashtext('sli_ad_snapshot_schedule392'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=391 and name='agent_receipt_summary')
       or exists(select 1 from public.schema_migrations where version>=392) then
        raise exception 'ad_snapshot_schedule392_preflight' using errcode='55000';
    end if;
end $$;

-- The baseline manifest table and its trigger function are owned by postgres.
reset role;
create or replace function public.ad_snapshot_manifest_apply_v2_schedule_header()
returns trigger language plpgsql as $$
declare
    expected_local_at timestamp without time zone;
begin
    if new.contract_version='sli.ad-snapshot-manifest/2.0' then
        new.schedule_timezone := coalesce(new.schedule_timezone,'Asia/Novosibirsk');
        if not exists(select 1 from pg_catalog.pg_timezone_names where name=new.schedule_timezone
                      and name not like 'posix/%' and name not like 'right/%') then
            raise exception 'invalid AD snapshot schedule time zone' using errcode='22023';
        end if;
        expected_local_at := new.slot_start_utc at time zone new.schedule_timezone;
        if new.scheduled_local_at is null then
            new.scheduled_local_at := expected_local_at;
        elsif new.scheduled_local_at is distinct from expected_local_at then
            raise exception 'AD snapshot schedule header does not match its UTC slot' using errcode='23514';
        end if;
    elsif new.contract_version='sli.ad-snapshot-manifest/1.0' then
        if new.schedule_timezone is not null or new.scheduled_local_at is not null then
            raise exception 'v1 AD snapshot manifests cannot declare a schedule header';
        end if;
    end if;
    return new;
end $$;

alter table public.ad_snapshot_manifests drop constraint ad_snapshot_manifests_slot_start_utc_check;
alter table public.ad_snapshot_manifests add constraint ad_snapshot_manifests_slot_start_utc_check check (
    (contract_version='sli.ad-snapshot-manifest/1.0' and schedule_timezone is null and scheduled_local_at is null
        and (slot_start_utc at time zone 'UTC')::time in (time '00:00',time '12:00'))
    or (contract_version='sli.ad-snapshot-manifest/2.0' and schedule_timezone is not null and scheduled_local_at is not null
        and scheduled_local_at::time in (time '06:00',time '18:00')
        and slot_start_utc=scheduled_local_at at time zone schedule_timezone)
    or (contract_version='sli.ad-snapshot-manifest/3.0' and schedule_timezone is not null and schedule_timezone='UTC'
        and scheduled_local_at is not null and scheduled_local_at=date_trunc('minute',scheduled_local_at)
        and slot_start_utc=scheduled_local_at at time zone 'UTC')
);

set local role adlog_storage_owner;
alter table public.sli_agent_snapshot_bindings add column follow_server_timezone boolean not null default false;
grant update(follow_server_timezone) on public.sli_agent_snapshot_bindings to adlog_user;
update public.sli_agent_snapshot_bindings b set follow_server_timezone=true
where b.enabled and b.config->>'policy_revision'='2'
  and exists(select 1 from public.sli_agent_audit a
      where a.action='module_assign' and a.actor like 'enrollment:%' and a.target=b.agent_id::text
        and a.details->>'module_id'=b.module_id and a.details->>'revision'='2');

insert into public.schema_migrations(version,name) values(392,'ad_snapshot_schedule');
reset role;
commit;
