-- Permit the existing projection consumer to read immutable exact overlays.
-- The consumer retains no ability to alter observations, receipts or evidence.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_radius_session_reconciliation_projection_v80')
);

do $$
begin
    if not exists (
        select 1 from schema_migrations
        where version=65
          and name='radius_session_reconciliation_overlay'
    ) then
        raise exception 'migration 080 requires schema migration 065';
    end if;
    if exists (
        select 1 from schema_migrations where version=80
    ) then
        raise exception 'migration 080 version is already recorded';
    end if;
    if to_regrole('adlog_radius_session_consumer') is null then
        raise exception 'migration 080 requires radius session consumer role';
    end if;
    if to_regclass('radius_session_identity_overlays') is null then
        raise exception 'migration 080 requires reconciliation overlays';
    end if;
end
$$;

set local role adlog_storage_owner;

grant select(
    observation_id,session_identity_key,exact_principal_key
) on radius_session_identity_overlays
to adlog_radius_session_consumer;

insert into schema_migrations(version,name)
values (80,'radius_session_reconciliation_projection');

commit;
