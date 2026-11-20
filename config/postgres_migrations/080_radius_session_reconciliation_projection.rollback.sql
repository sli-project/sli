-- Revoke the derived projection read grant only before any immutable overlay.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_radius_session_reconciliation_projection_v80')
);

do $$
begin
    if exists(select 1 from radius_session_identity_overlays) then
        raise exception 'rollback 080 forbidden after reconciliation overlays';
    end if;
end
$$;

set local role adlog_storage_owner;

revoke select(
    observation_id,session_identity_key,exact_principal_key
) on radius_session_identity_overlays
from adlog_radius_session_consumer;

delete from schema_migrations
where version=80
  and name='radius_session_reconciliation_projection';

commit;
