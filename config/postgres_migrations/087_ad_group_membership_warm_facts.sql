-- Stage G11A6: source-native member identity and controlled-group scope
-- for bounded AD group-change evidence.
-- Source-only schema preparation: no source, worker, runtime or deployment change.
--
-- Two different tables are altered here under two different owning roles:
-- event_facts_v2 is owned by adlog_storage_owner, ad_context_runs is owned
-- by adlog_user. adlog_storage_owner is a member of adlog_user but is
-- NOINHERIT, so membership alone does not grant it ad_context_runs's owner
-- privileges - each ALTER TABLE runs under an explicit `set local role`
-- matching that statement's own target table, the same multi-role-switch
-- shape migrations 062/083 already use for the same reason.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_ad_group_membership_warm_facts_v87')
);

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 087 requires membership in adlog_storage_owner';
    end if;
    if not pg_has_role(session_user, 'adlog_user', 'MEMBER') then
        raise exception 'migration 087 requires membership in adlog_user';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=86 and name='ad_account_change_warm_facts'
    ) then
        raise exception 'migration 087 requires migration 086';
    end if;
    if exists(select 1 from schema_migrations where version=87) then
        raise exception 'migration 087 version is already recorded';
    end if;
    if to_regclass('event_facts_v2') is null then
        raise exception 'migration 087 requires event_facts_v2';
    end if;
    if to_regclass('ad_context_runs') is null then
        raise exception 'migration 087 requires ad_context_runs';
    end if;
end
$$;

set local role adlog_storage_owner;

alter table event_facts_v2
    add column membership_member_sid text,
    add column membership_member_name text,
    add constraint event_facts_v2_membership_member_sid_bounded
        check (membership_member_sid is null or length(membership_member_sid) <= 512),
    add constraint event_facts_v2_membership_member_name_bounded
        check (membership_member_name is null or length(membership_member_name) <= 512);

set local role adlog_user;

alter table ad_context_runs
    add column scope_json jsonb,
    add constraint ad_context_runs_scope_json_object
        check (scope_json is null or jsonb_typeof(scope_json) = 'object');

set local role adlog_storage_owner;

insert into schema_migrations(version,name)
values (87,'ad_group_membership_warm_facts')
on conflict(version) do update set name=excluded.name;

commit;
