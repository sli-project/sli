-- Evidence-preserving rollback for migration 087.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_ad_group_membership_warm_facts_v87')
);

do $$
begin
    if not exists (
        select 1 from schema_migrations
        where version=87 and name='ad_group_membership_warm_facts'
    ) then
        raise exception 'migration 087 rollback requires its marker';
    end if;
    if exists(
        select 1 from event_facts_v2
        where membership_member_sid is not null
           or membership_member_name is not null
    ) then
        raise exception 'rollback is unsafe while group membership facts exist';
    end if;
    if exists(select 1 from ad_context_runs where scope_json is not null) then
        raise exception 'rollback is unsafe while AD Context scopes exist';
    end if;
end
$$;

set local role adlog_storage_owner;

alter table event_facts_v2
    drop constraint event_facts_v2_membership_member_sid_bounded,
    drop constraint event_facts_v2_membership_member_name_bounded,
    drop column membership_member_sid,
    drop column membership_member_name;

set local role adlog_user;

alter table ad_context_runs
    drop constraint ad_context_runs_scope_json_object,
    drop column scope_json;

set local role adlog_storage_owner;

delete from schema_migrations
where version=87 and name='ad_group_membership_warm_facts';

commit;
