-- Refuse removal after the resolver has contributed runtime evidence/state.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_radius_identity_spine_resolver_v59')
);

do $$
declare
    persisted bigint;
begin
    select
        coalesce((select count(*) from core_evidence_manifests),0)
      + coalesce(
            (select count(*) from radius_accounting_session_observations),0
        )
      + coalesce((select count(*) from acquisition_delivery_outbox),0)
      + coalesce((select count(*) from radius_accounting_class_cache),0)
    into persisted;
    if persisted > 0 then
        raise exception
            'migration 059 rollback refuses persisted RADIUS runtime state: % rows',
            persisted;
    end if;
end
$$;

set local role adlog_storage_owner;

revoke all on function sli_radius_resolve_principal_key(text,text)
from adlog_radius_accounting_worker;
drop function if exists sli_radius_resolve_principal_key(text,text);

delete from schema_migrations
where version=59 and name='radius_identity_spine_resolver';

commit;
