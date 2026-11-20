-- Stage G11A6: source-native rename names for bounded AD account-change evidence.
-- Source-only schema preparation: no source, worker, runtime or deployment change.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_ad_account_change_warm_facts_v86')
);

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 086 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=85 and name='dc_powershell_origin_context'
    ) then
        raise exception 'migration 086 requires migration 085';
    end if;
    if exists(select 1 from schema_migrations where version=86) then
        raise exception 'migration 086 version is already recorded';
    end if;
    if to_regclass('event_facts_v2') is null then
        raise exception 'migration 086 requires event_facts_v2';
    end if;
end
$$;

set local role adlog_storage_owner;

alter table event_facts_v2
    add column account_target_sid text,
    add column account_target_name text,
    add column account_name_before text,
    add column account_name_after text,
    add constraint event_facts_v2_account_target_sid_bounded
        check (account_target_sid is null or length(account_target_sid) <= 512),
    add constraint event_facts_v2_account_target_name_bounded
        check (account_target_name is null or length(account_target_name) <= 512),
    add constraint event_facts_v2_account_name_before_bounded
        check (account_name_before is null or length(account_name_before) <= 512),
    add constraint event_facts_v2_account_name_after_bounded
        check (account_name_after is null or length(account_name_after) <= 512);

insert into schema_migrations(version,name)
values (86,'ad_account_change_warm_facts')
on conflict(version) do update set name=excluded.name;

commit;
