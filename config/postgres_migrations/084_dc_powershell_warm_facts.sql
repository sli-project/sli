-- Stage G11A6: bounded source-native PowerShell facts for a DC-only read path.
-- Source-only schema preparation: no source, worker, runtime or deployment change.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_dc_powershell_warm_facts_v84')
);

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 084 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=9 and name='storage_v2_foundation'
    ) then
        raise exception 'migration 084 requires migration 009';
    end if;
    if exists(select 1 from schema_migrations where version=84) then
        raise exception 'migration 084 version is already recorded';
    end if;
    if to_regclass('event_facts_v2') is null then
        raise exception 'migration 084 requires event_facts_v2';
    end if;
end
$$;

set local role adlog_storage_owner;

alter table event_facts_v2
    add column if not exists powershell_user_name text,
    add column if not exists powershell_command_name text,
    add column if not exists powershell_script_block_text text;

do $$
begin
    if not exists (
        select 1 from pg_constraint
        where conrelid='event_facts_v2'::regclass
          and conname='event_facts_v2_powershell_user_bounded'
    ) then
        alter table event_facts_v2
            add constraint event_facts_v2_powershell_user_bounded
            check (powershell_user_name is null or length(powershell_user_name) <= 512);
    end if;
    if not exists (
        select 1 from pg_constraint
        where conrelid='event_facts_v2'::regclass
          and conname='event_facts_v2_powershell_command_bounded'
    ) then
        alter table event_facts_v2
            add constraint event_facts_v2_powershell_command_bounded
            check (powershell_command_name is null or length(powershell_command_name) <= 512);
    end if;
    if not exists (
        select 1 from pg_constraint
        where conrelid='event_facts_v2'::regclass
          and conname='event_facts_v2_powershell_script_block_bounded'
    ) then
        alter table event_facts_v2
            add constraint event_facts_v2_powershell_script_block_bounded
            check (powershell_script_block_text is null or length(powershell_script_block_text) <= 2048);
    end if;
end
$$;

insert into schema_migrations(version,name)
values (84,'dc_powershell_warm_facts')
on conflict(version) do update set name=excluded.name;

commit;
