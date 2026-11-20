-- Preserve all source, cursor, evidence, fact, outbox and cache rows.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_radius_accounting_transaction_v58')
);

do $$
declare
    persisted bigint;
begin
    select
        coalesce((select count(*) from acquisition_source_instances),0)
      + coalesce((select count(*) from acquisition_stream_cursors),0)
      + coalesce((select count(*) from acquisition_consumer_subscriptions),0)
      + coalesce((select count(*) from core_evidence_manifests),0)
      + coalesce((select count(*) from radius_accounting_session_observations),0)
      + coalesce((select count(*) from acquisition_delivery_outbox),0)
      + coalesce((select count(*) from radius_accounting_class_cache),0)
    into persisted;
    if persisted > 0 then
        raise exception
            'migration 058 rollback refuses persisted acquisition evidence/state: % rows',
            persisted;
    end if;
end
$$;

set local role adlog_storage_owner;

drop table if exists acquisition_delivery_outbox;
drop table if exists radius_accounting_session_observations;
drop table if exists radius_accounting_class_cache;
drop table if exists core_evidence_manifests;
drop table if exists acquisition_consumer_subscriptions;
drop table if exists acquisition_stream_cursors;
drop table if exists acquisition_source_instances;

delete from schema_migrations
where version=58 and name='radius_accounting_transaction_foundation';

reset role;
revoke adlog_radius_accounting_worker from adlog_storage_owner;
drop role adlog_radius_accounting_worker;

commit;
