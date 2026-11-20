-- Evidence-preserving rollback for migration 086.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_ad_account_change_warm_facts_v86')
);

do $$
begin
    if not exists (
        select 1 from schema_migrations
        where version=86 and name='ad_account_change_warm_facts'
    ) then
        raise exception 'migration 086 rollback requires its marker';
    end if;
    if exists(
        select 1 from event_facts_v2
        where account_target_sid is not null
           or account_target_name is not null
           or account_name_before is not null
           or account_name_after is not null
    ) then
        raise exception 'rollback is unsafe while account rename facts exist';
    end if;
end
$$;

set local role adlog_storage_owner;

alter table event_facts_v2
    drop constraint event_facts_v2_account_target_sid_bounded,
    drop constraint event_facts_v2_account_target_name_bounded,
    drop constraint event_facts_v2_account_name_before_bounded,
    drop constraint event_facts_v2_account_name_after_bounded,
    drop column account_target_sid,
    drop column account_target_name,
    drop column account_name_before,
    drop column account_name_after;

delete from schema_migrations
where version=86 and name='ad_account_change_warm_facts';

commit;
