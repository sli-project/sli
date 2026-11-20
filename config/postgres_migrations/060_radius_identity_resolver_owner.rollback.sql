-- Restore migration 059 ownership only before any RADIUS runtime state.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_radius_identity_resolver_owner_v60')
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
            'migration 060 rollback refuses persisted RADIUS runtime state: % rows',
            persisted;
    end if;
end
$$;

alter function sli_radius_resolve_principal_key(text,text)
owner to adlog_storage_owner;
revoke all on function sli_radius_resolve_principal_key(text,text)
from public;
grant execute on function sli_radius_resolve_principal_key(text,text)
to adlog_radius_accounting_worker;

set local role adlog_storage_owner;

delete from schema_migrations
where version=60 and name='radius_identity_resolver_owner';

reset role;

revoke adlog_radius_identity_resolver from adlog_storage_owner;
revoke all on table domains from adlog_radius_identity_resolver;
revoke all on table ad_context_entity_aliases
from adlog_radius_identity_resolver;
revoke usage on schema public from adlog_radius_identity_resolver;
drop role adlog_radius_identity_resolver;

commit;
