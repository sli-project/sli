-- Give the SECURITY DEFINER resolver an exact least-privilege owner.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_radius_identity_resolver_owner_v60')
);

do $$
begin
    if not exists (
        select 1 from schema_migrations
        where version=59 and name='radius_identity_spine_resolver'
    ) then
        raise exception 'migration 060 requires migration 059';
    end if;
    if to_regprocedure(
        'sli_radius_resolve_principal_key(text,text)'
    ) is null then
        raise exception 'migration 060 requires radius resolver function';
    end if;
    if to_regrole('adlog_radius_identity_resolver') is not null then
        raise exception 'migration 060 requires absent resolver owner role';
    end if;
end
$$;

create role adlog_radius_identity_resolver
    noinherit nologin nosuperuser nocreatedb nocreaterole
    nobypassrls noreplication;
grant adlog_radius_identity_resolver to adlog_storage_owner;

grant usage,create on schema public to adlog_radius_identity_resolver;
grant select(id,fqdn) on table domains
to adlog_radius_identity_resolver;
grant select(entity_id,domain_id,alias_type,normalized_value)
on table ad_context_entity_aliases
to adlog_radius_identity_resolver;

set local role adlog_storage_owner;

revoke all on function sli_radius_resolve_principal_key(text,text)
from public;
grant execute on function sli_radius_resolve_principal_key(text,text)
to adlog_radius_accounting_worker;
alter function sli_radius_resolve_principal_key(text,text)
owner to adlog_radius_identity_resolver;

reset role;
revoke create on schema public from adlog_radius_identity_resolver;
set local role adlog_storage_owner;

insert into schema_migrations(version,name)
values(60,'radius_identity_resolver_owner')
on conflict(version) do update set name=excluded.name;

commit;
