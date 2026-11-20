begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_canonical_action_state_evidence_v24_rollback'));
do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'rollback 024 requires membership in adlog_storage_owner';
    end if;
    if exists (select 1 from canonical_action_state_evidence) then
        raise exception 'rollback 024 refused: canonical action state evidence exists';
    end if;
end $$;
set local role adlog_storage_owner;
drop table if exists canonical_action_state_evidence;
delete from schema_migrations where version=24 and name='canonical_action_state_evidence';
commit;
