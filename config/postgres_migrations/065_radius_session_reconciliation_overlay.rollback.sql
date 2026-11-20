-- Roll back only before any immutable reconciliation evidence exists.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_radius_session_reconciliation_v65')
);

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'rollback 065 requires membership in adlog_storage_owner';
    end if;
    if exists (select 1 from schema_migrations where version>65) then
        raise exception 'rollback 065 is blocked by later migrations';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=65 and name='radius_session_reconciliation_overlay'
    ) then
        raise exception 'rollback 065 requires schema migration 065';
    end if;
    if exists (select 1 from radius_session_identity_overlays)
       or exists (select 1 from radius_session_reconciliation_attempts) then
        raise exception 'rollback 065 forbidden after reconciliation evidence';
    end if;
end
$$;

set local role adlog_storage_owner;
drop index radius_session_reconciliation_attempt_observation_idx;
drop table radius_session_identity_overlays;
drop table radius_session_reconciliation_attempts;
delete from schema_migrations
where version=65 and name='radius_session_reconciliation_overlay';
reset role;

revoke select(id) on entities_v2
from adlog_radius_session_reconciliation_writer;
revoke select(observation_id,outcome)
on radius_session_projection_receipts
from adlog_radius_session_reconciliation_writer;
revoke select(observation_id,evidence_uid,identity_state)
on radius_accounting_session_observations
from adlog_radius_session_reconciliation_writer;
revoke usage on schema public
from adlog_radius_session_reconciliation_writer;
revoke adlog_radius_session_reconciliation_writer from adlog_storage_owner;
drop role adlog_radius_session_reconciliation_writer;

commit;
