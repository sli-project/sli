-- SEMANTIC-2 rollback refuses to downgrade more specific evidence silently.

begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_canonical_action_statuses_v23_rollback'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'rollback 023 requires membership in adlog_storage_owner';
    end if;
    if exists (
        select 1 from canonical_actions
        where action_status in ('partially_confirmed', 'state_confirmed', 'multi_source_confirmed', 'contradicted')
    ) then
        raise exception 'rollback 023 refused: canonical action confirmation states exist';
    end if;
end
$$;

set local role adlog_storage_owner;

alter table canonical_actions drop constraint if exists canonical_actions_action_status_check;
alter table canonical_actions
    add constraint canonical_actions_action_status_check
    check (action_status in ('observed', 'confirmed', 'superseded', 'quarantined'));

delete from schema_migrations
where version=23 and name='canonical_action_confirmation_statuses';

commit;
