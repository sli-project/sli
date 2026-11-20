-- Narrow exact DN -> canonical entity key bridge for the manual RADIUS worker.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_radius_identity_spine_resolver_v59')
);

do $$
begin
    if not exists (
        select 1 from schema_migrations
        where version=58
          and name='radius_accounting_transaction_foundation'
    ) then
        raise exception 'migration 059 requires migration 058';
    end if;
    if to_regrole('adlog_radius_accounting_worker') is null then
        raise exception 'migration 059 requires radius worker role';
    end if;
end
$$;

set local role adlog_storage_owner;

create or replace function sli_radius_resolve_principal_key(
    organization_fqdn text,
    distinguished_name text
)
returns text
language sql
stable
strict
security definer
set search_path = pg_catalog, public
as $$
    select case
        when count(*) = 1 then 'entity:' || min(alias.entity_id)::text
        else null
    end
    from public.ad_context_entity_aliases alias
    join public.domains domain_row on domain_row.id=alias.domain_id
    where char_length(btrim(organization_fqdn)) between 1 and 255
      and char_length(btrim(distinguished_name)) between 1 and 2048
      and lower(domain_row.fqdn)=lower(btrim(organization_fqdn))
      and alias.alias_type='distinguished_name'
      and alias.normalized_value=lower(btrim(distinguished_name))
$$;

revoke all on function sli_radius_resolve_principal_key(text,text)
from public;
grant execute on function sli_radius_resolve_principal_key(text,text)
to adlog_radius_accounting_worker;

insert into schema_migrations(version,name)
values (59,'radius_identity_spine_resolver')
on conflict(version) do update set name=excluded.name;

commit;
