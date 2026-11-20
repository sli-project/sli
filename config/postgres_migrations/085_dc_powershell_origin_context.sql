-- Stage G11A6: source-native PowerShell process identity for bounded origin proof.
-- Source-only schema preparation: no source, worker, runtime or deployment change.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_dc_powershell_origin_context_v85')
);

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 085 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=84 and name='dc_powershell_warm_facts'
    ) then
        raise exception 'migration 085 requires migration 084';
    end if;
    if exists(select 1 from schema_migrations where version=85) then
        raise exception 'migration 085 version is already recorded';
    end if;
    if to_regclass('event_facts_v2') is null then
        raise exception 'migration 085 requires event_facts_v2';
    end if;
end
$$;

set local role adlog_storage_owner;

alter table event_facts_v2
    add column if not exists powershell_process_id text;

do $$
begin
    if not exists (
        select 1 from pg_constraint
        where conrelid='event_facts_v2'::regclass
          and conname='event_facts_v2_powershell_process_id_bounded'
    ) then
        alter table event_facts_v2
            add constraint event_facts_v2_powershell_process_id_bounded
            check (powershell_process_id is null or length(powershell_process_id) <= 128);
    end if;
end
$$;

insert into schema_migrations(version,name)
values (85,'dc_powershell_origin_context')
on conflict(version) do update set name=excluded.name;

commit;
