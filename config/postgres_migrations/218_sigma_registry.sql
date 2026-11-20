-- Sigma stage 10: dormant, scope-bound, append-only rule/overlay registry.
begin;
select pg_advisory_xact_lock(hashtext('sli_sigma_registry_v218'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=217 and name='agent_inbox_quota_payload_bytes')
       or exists(select 1 from public.schema_migrations where version>=218) then
        raise exception 'migration 218 prerequisites failed';
    end if;
    if to_regnamespace('sli_sigma') is not null
       or to_regrole('adlog_sigma_owner') is not null
       or to_regrole('adlog_sigma_reader') is not null
       or to_regrole('adlog_sigma_writer') is not null then
        raise exception 'migration 218 requires absent Sigma namespace and roles';
    end if;
end $$;
create role adlog_sigma_owner nologin noinherit nosuperuser nocreatedb nocreaterole nobypassrls noreplication;
create role adlog_sigma_reader nologin noinherit nosuperuser nocreatedb nocreaterole nobypassrls noreplication;
create role adlog_sigma_writer nologin noinherit nosuperuser nocreatedb nocreaterole nobypassrls noreplication;
grant adlog_sigma_owner to adlog_storage_owner;
create schema sli_sigma authorization adlog_sigma_owner;
revoke all on schema sli_sigma from public,adlog_user;
grant usage on schema sli_sigma to adlog_sigma_reader,adlog_sigma_writer;
set local role adlog_sigma_owner;

-- Provisioned by the storage administrator, never by a supplied YAML, request
-- parameter or user-set GUC. Empty ACL / no login memberships is the default.
create table sli_sigma.scope_access (
    principal_oid oid not null,
    principal_name name not null,
    installation_id uuid not null,
    plugin_id text not null check(length(plugin_id) between 1 and 128),
    source_instance_id text not null check(length(source_instance_id) between 1 and 256),
    can_write boolean not null default false,
    primary key(principal_oid,installation_id,plugin_id,source_instance_id)
);
revoke all on sli_sigma.scope_access from public,adlog_user,adlog_sigma_reader,adlog_sigma_writer;

create function sli_sigma.scope_allowed(p_installation uuid,p_plugin text,p_source text,p_write boolean)
returns boolean language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select exists(select 1 from sli_sigma.scope_access a join pg_catalog.pg_roles r
        on r.oid=a.principal_oid and r.rolname=a.principal_name
        where r.rolname=session_user and a.installation_id=p_installation
          and a.plugin_id=p_plugin and a.source_instance_id=p_source
          and (not p_write or a.can_write));
$$;
revoke all on function sli_sigma.scope_allowed(uuid,text,text,boolean) from public;
grant execute on function sli_sigma.scope_allowed(uuid,text,text,boolean) to adlog_sigma_reader,adlog_sigma_writer;

create table sli_sigma.sigma_rule_revisions (
    installation_id uuid not null,
    plugin_id text not null check(length(plugin_id) between 1 and 128),
    source_instance_id text not null check(length(source_instance_id) between 1 and 256),
    rule_id uuid not null,
    raw_yaml text not null check(octet_length(raw_yaml) between 1 and 1048576),
    raw_sha256 text not null check(raw_sha256 ~ '^[a-f0-9]{64}$'),
    canonical_rule jsonb not null check(jsonb_typeof(canonical_rule)='object'
        and octet_length(canonical_rule::text)<=4194304
        and canonical_rule->>'id' is not distinct from rule_id::text),
    -- Canonical hashes use PostgreSQL JSONB text, not compiler plan hashes.
    canonical_sha256 text not null check(canonical_sha256 ~ '^[a-f0-9]{64}$'),
    upstream_commit text not null check(upstream_commit ~ '^[a-f0-9]{40}$'),
    status text not null check(status in ('stable','test','experimental','deprecated','unsupported')),
    level text not null check(level in ('informational','low','medium','high','critical')),
    tags jsonb not null check(jsonb_typeof(tags)='array' and jsonb_array_length(tags)<=128 and octet_length(tags::text)<=16384),
    author text not null check(length(author) between 1 and 4096),
    license text not null check(length(license) between 1 and 128),
    source_uri text not null check(length(source_uri) between 1 and 2048),
    created_at timestamptz not null default clock_timestamp(),
    created_by name not null default session_user,
    primary key(installation_id,plugin_id,source_instance_id,rule_id,raw_sha256),
    unique(installation_id,plugin_id,source_instance_id,rule_id,raw_sha256,canonical_sha256)
);
create table sli_sigma.sigma_source_requirements (
    installation_id uuid not null,
    plugin_id text not null,
    source_instance_id text not null,
    rule_id uuid not null,
    raw_sha256 text not null,
    requirements jsonb not null check(jsonb_typeof(requirements)='object' and octet_length(requirements::text)<=65536),
    requirements_sha256 text not null check(requirements_sha256 ~ '^[a-f0-9]{64}$'),
    primary key(installation_id,plugin_id,source_instance_id,rule_id,raw_sha256),
    foreign key(installation_id,plugin_id,source_instance_id,rule_id,raw_sha256)
        references sli_sigma.sigma_rule_revisions(installation_id,plugin_id,source_instance_id,rule_id,raw_sha256)
);

-- A small stored predicate dialect; no SQL, shell, YAML patch or executable plan.
-- Evaluation and base-version conflict handling belong to subsequent stages.
create function sli_sigma.valid_overlay(p jsonb) returns boolean
language plpgsql immutable security invoker set search_path=pg_catalog,pg_temp as $$
declare v jsonb;
begin
    if p is null or jsonb_typeof(p) is distinct from 'object'
       or p->>'version' is distinct from 'sli.sigma.overlay.v1'
       or p - 'version' - 'all_of' <> '{}'::jsonb
       or jsonb_typeof(p->'all_of') is distinct from 'array' then return false; end if;
    if jsonb_array_length(p->'all_of') not between 1 and 32 or octet_length(p::text)>65536 then return false; end if;
    for v in select jsonb_array_elements(p->'all_of') loop
        if jsonb_typeof(v) is distinct from 'object' or v - 'field' - 'equals' <> '{}'::jsonb
           or jsonb_typeof(v->'field') is distinct from 'string'
           or (v->>'field') !~ '^[A-Za-z][A-Za-z0-9_]{0,127}$'
           or not (v ? 'equals') or jsonb_typeof(v->'equals') not in ('string','number','boolean','null')
           or octet_length(v::text)>8192 then return false; end if;
    end loop;
    return true;
end $$;
revoke all on function sli_sigma.valid_overlay(jsonb) from public;
grant execute on function sli_sigma.valid_overlay(jsonb) to adlog_sigma_reader,adlog_sigma_writer;

create table sli_sigma.sigma_rule_overlays (
    installation_id uuid not null,
    plugin_id text not null,
    source_instance_id text not null,
    overlay_id uuid not null,
    version integer not null check(version>0),
    rule_id uuid not null,
    base_raw_sha256 text not null,
    base_canonical_sha256 text not null,
    mapping_version text not null check(length(mapping_version) between 1 and 128),
    predicate jsonb not null check(sli_sigma.valid_overlay(predicate)),
    overlay_sha256 text not null check(overlay_sha256 ~ '^[a-f0-9]{64}$'),
    reason text not null check(length(reason) between 1 and 4096),
    expires_at timestamptz not null check(isfinite(expires_at) and expires_at>created_at),
    created_at timestamptz not null default clock_timestamp(),
    created_by name not null default session_user,
    primary key(installation_id,plugin_id,source_instance_id,overlay_id,version),
    foreign key(installation_id,plugin_id,source_instance_id,rule_id,base_raw_sha256,base_canonical_sha256)
        references sli_sigma.sigma_rule_revisions(installation_id,plugin_id,source_instance_id,rule_id,raw_sha256,canonical_sha256)
);

-- Hashes and provenance are computed at the storage boundary, not trusted from
-- the importer. A trigger also avoids session-dependent generated expressions.
create function sli_sigma.stamp_insert() returns trigger
language plpgsql security invoker set search_path=pg_catalog,pg_temp as $$
begin
    if tg_table_name='sigma_rule_revisions' then
        new.raw_sha256 := encode(sha256(convert_to(new.raw_yaml,'UTF8')),'hex');
        new.canonical_sha256 := encode(sha256(convert_to(new.canonical_rule::text,'UTF8')),'hex');
    elsif tg_table_name='sigma_source_requirements' then
        new.requirements_sha256 := encode(sha256(convert_to(new.requirements::text,'UTF8')),'hex');
        return new;
    else
        new.overlay_sha256 := encode(sha256(convert_to(jsonb_build_object(
            'installation_id',new.installation_id,'plugin_id',new.plugin_id,'source_instance_id',new.source_instance_id,
            'overlay_id',new.overlay_id,'version',new.version,'rule_id',new.rule_id,
            'base_raw_sha256',new.base_raw_sha256,'base_canonical_sha256',new.base_canonical_sha256,
            'mapping_version',new.mapping_version,'predicate',new.predicate,'reason',new.reason,
            'expires_at',to_char(new.expires_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))::text,'UTF8')),'hex');
    end if;
    new.created_at := clock_timestamp();
    new.created_by := session_user;
    return new;
end $$;
revoke all on function sli_sigma.stamp_insert() from public;

create function sli_sigma.reject_mutation() returns trigger
language plpgsql security invoker set search_path=pg_catalog,pg_temp as $$
begin raise exception 'sigma_registry_immutable' using errcode='42501'; end $$;
revoke all on function sli_sigma.reject_mutation() from public;

do $$ declare t text; begin
    foreach t in array array['sigma_rule_revisions','sigma_source_requirements','sigma_rule_overlays'] loop
        execute format('revoke all on sli_sigma.%I from public,adlog_user,adlog_sigma_reader,adlog_sigma_writer',t);
        execute format('alter table sli_sigma.%I enable row level security',t);
        execute format('create policy scoped_read on sli_sigma.%I for select to adlog_sigma_reader,adlog_sigma_writer
            using (sli_sigma.scope_allowed(installation_id,plugin_id,source_instance_id,false))',t);
        execute format('create policy scoped_insert on sli_sigma.%I for insert to adlog_sigma_writer
            with check (sli_sigma.scope_allowed(installation_id,plugin_id,source_instance_id,true))',t);
        execute format('grant select on sli_sigma.%I to adlog_sigma_reader,adlog_sigma_writer',t);
        execute format('create trigger stamp_insert before insert on sli_sigma.%I
            for each row execute function sli_sigma.stamp_insert()',t);
        execute format('create trigger immutable_rows before update or delete on sli_sigma.%I
            for each row execute function sli_sigma.reject_mutation()',t);
        execute format('create trigger immutable_truncate before truncate on sli_sigma.%I
            for each statement execute function sli_sigma.reject_mutation()',t);
    end loop;
end $$;
-- Do not allow importers to forge storage provenance or computed hashes.
grant insert(installation_id,plugin_id,source_instance_id,rule_id,raw_yaml,canonical_rule,
    upstream_commit,status,level,tags,author,license,source_uri)
    on sli_sigma.sigma_rule_revisions to adlog_sigma_writer;
grant insert(installation_id,plugin_id,source_instance_id,rule_id,raw_sha256,requirements)
    on sli_sigma.sigma_source_requirements to adlog_sigma_writer;
grant insert(installation_id,plugin_id,source_instance_id,overlay_id,version,rule_id,base_raw_sha256,
    base_canonical_sha256,mapping_version,predicate,reason,expires_at)
    on sli_sigma.sigma_rule_overlays to adlog_sigma_writer;
reset role;
set local role adlog_storage_owner;
insert into public.schema_migrations(version,name) values(218,'sigma_registry');
commit;
