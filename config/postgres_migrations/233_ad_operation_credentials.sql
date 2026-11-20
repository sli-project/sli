-- Explicit AD operation assignments; no automatic owner/admin grants or AD writes.
begin;
select pg_advisory_xact_lock(hashtext('sli_ad_operation_credentials_v233'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=232 and name='file_ransom')
       or exists(select 1 from public.schema_migrations where version>=233) then
        raise exception 'migration 233 prerequisites failed';
    end if;
end $$;
set local role adlog_storage_owner;

create table public.sli_ad_credential_installation (
    singleton boolean primary key default true check(singleton),
    installation_id uuid not null unique default gen_random_uuid()
);
insert into public.sli_ad_credential_installation(singleton) values(true);
create table public.sli_ad_operations_grants (
    actor text not null check(actor ~ '^session:[1-9][0-9]*$'),
    domain_id bigint not null references public.domains(id) on delete restrict,
    ou_entity_ids bigint[] not null check(cardinality(ou_entity_ids) between 1 and 128
        and array_position(ou_entity_ids,null) is null),
    enabled boolean not null default true,
    primary key(actor,domain_id)
);
create table public.sli_ad_operation_credentials (
    credential_id uuid primary key,
    installation_id uuid not null references public.sli_ad_credential_installation(installation_id),
    domain_id bigint not null references public.domains(id) on delete restrict,
    ou_entity_ids bigint[] not null check(cardinality(ou_entity_ids) between 1 and 128
        and array_position(ou_entity_ids,null) is null),
    label text not null check(length(label) between 1 and 128),
    username text not null check(length(username) between 1 and 1024),
    credential_revision bigint not null default 1 check(credential_revision>0),
    envelope jsonb not null check(jsonb_typeof(envelope)='object'
        and envelope->>'format_version'='1' and (envelope->>'key_version')::bigint>0
        and envelope ?& array['ciphertext','nonce','wrapped_dek','wrap_nonce']),
    created_by text not null,
    created_at timestamptz not null default clock_timestamp(),
    updated_by text not null,
    updated_at timestamptz not null default clock_timestamp(),
    check_status text not null default 'not_checked' check(check_status in ('not_checked','unavailable')),
    checked_at timestamptz
);
create index sli_ad_operation_credentials_domain on public.sli_ad_operation_credentials(domain_id);
create table public.sli_ad_credential_audit (
    id bigint generated always as identity primary key,
    occurred_at timestamptz not null default clock_timestamp(),
    actor text not null,
    domain_id bigint references public.domains(id) on delete restrict,
    credential_id uuid,
    credential_revision bigint,
    action text not null check(action in ('created','password_replaced','deleted','check_blocked','denied')),
    result text not null
);
revoke all on public.sli_ad_credential_installation,public.sli_ad_operations_grants,
    public.sli_ad_operation_credentials,public.sli_ad_credential_audit from public;

-- Runtime cannot grant itself Operations in AD. Hold assignment locks through
-- the credential transaction so revocation cannot race a mutation.
create function public.sli_ad_operations_scopes(p_actor text) returns jsonb
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare result jsonb;
begin
    select coalesce(jsonb_agg(to_jsonb(g)), '[]'::jsonb) into result from (
        select domain_id,ou_entity_ids from public.sli_ad_operations_grants
        where actor=p_actor and enabled is true order by domain_id for share
    ) g;
    return result;
end $$;
revoke all on function public.sli_ad_operations_scopes(text) from public;
grant execute on function public.sli_ad_operations_scopes(text) to adlog_user;
grant select on public.sli_ad_credential_installation to adlog_user;
grant select,insert,delete on public.sli_ad_operation_credentials to adlog_user;
grant update(envelope,credential_revision,updated_at,updated_by,check_status,checked_at)
    on public.sli_ad_operation_credentials to adlog_user;
grant insert on public.sli_ad_credential_audit to adlog_user;
grant usage on sequence public.sli_ad_credential_audit_id_seq to adlog_user;
reset role;
insert into public.schema_migrations(version,name) values(233,'ad_operation_credentials');
commit;
