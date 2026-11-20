-- Sigma stage 18: immutable, scope-bound aggregate reporting, no raw evidence.
begin;
select pg_advisory_xact_lock(hashtext('sli_sigma_attack_coverage_v222'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=221 and name='sigma_chain_plugins')
       or exists(select 1 from public.schema_migrations where version>=222) then
        raise exception 'migration 222 prerequisites failed';
    end if;
end $$;
set local role adlog_sigma_owner;

create table sli_sigma.attack_catalogs (
    stix_sha256 text primary key check(stix_sha256 ~ '^[a-f0-9]{64}$'),
    document_json jsonb not null check(jsonb_typeof(document_json)='object'
        and jsonb_typeof(document_json->'techniques')='object'
        and octet_length(document_json::text)<=4194304)
);
create table sli_sigma.attack_source_scopes (
    installation_id uuid not null,
    plugin_id text not null check(length(plugin_id) between 1 and 128),
    source_instance_id text not null check(length(source_instance_id) between 1 and 256),
    source_generation text not null check(length(source_generation) between 1 and 512),
    collection_scope_id text not null default '' check(length(collection_scope_id)<=256),
    resources jsonb not null check(jsonb_typeof(resources)='array'
        and jsonb_array_length(resources) between 1 and 16 and octet_length(resources::text)<=16384),
    primary key(installation_id,plugin_id,source_instance_id,source_generation,collection_scope_id)
);
create table sli_sigma.attack_history_coverage (
    installation_id uuid not null,
    plugin_id text not null,
    source_instance_id text not null,
    source_generation text not null,
    collection_scope_id text not null default '',
    rule_id uuid not null,
    raw_sha256 text not null,
    time_from timestamptz not null,
    time_to timestamptz not null check(time_to>time_from and time_to<=time_from+interval '1 day'),
    document_json jsonb not null check(jsonb_typeof(document_json)='object'
        and document_json->>'version' is not distinct from 'sli.sigma.attack-coverage.v1'
        and document_json->>'mode' is not distinct from 'test'
        and octet_length(document_json::text)<=65536),
    coverage_sha256 text not null check(coverage_sha256 ~ '^[a-f0-9]{64}$'),
    created_at timestamptz not null default clock_timestamp(),
    primary key(installation_id,plugin_id,source_instance_id,source_generation,collection_scope_id,
        rule_id,raw_sha256,time_from,time_to,coverage_sha256),
    foreign key(installation_id,plugin_id,source_instance_id,source_generation,collection_scope_id)
        references sli_sigma.attack_source_scopes,
    foreign key(installation_id,plugin_id,source_instance_id,rule_id,raw_sha256)
        references sli_sigma.sigma_rule_revisions(installation_id,plugin_id,source_instance_id,rule_id,raw_sha256)
);
create index attack_history_coverage_window on sli_sigma.attack_history_coverage
    (installation_id,plugin_id,source_instance_id,source_generation,collection_scope_id,time_from,time_to);
create function sli_sigma.stamp_attack_coverage() returns trigger
language plpgsql security invoker set search_path=pg_catalog,pg_temp as $$ begin
    new.coverage_sha256 := encode(sha256(convert_to(new.document_json::text,'UTF8')),'hex');
    new.created_at := clock_timestamp();
    return new;
end $$;
revoke all on function sli_sigma.stamp_attack_coverage() from public;
create trigger stamp_insert before insert on sli_sigma.attack_history_coverage
    for each row execute function sli_sigma.stamp_attack_coverage();

revoke all on sli_sigma.attack_catalogs,sli_sigma.attack_source_scopes,sli_sigma.attack_history_coverage
    from public,adlog_user,adlog_sigma_reader,adlog_sigma_writer;
-- Runtime can read reporting metadata only, never YAML, predicates or source payloads.
grant usage on schema sli_sigma to adlog_user;
grant execute on function sli_sigma.scope_allowed(uuid,text,text,boolean) to adlog_user;
grant usage on schema sli_sigma to adlog_storage_owner;
grant execute on function sli_sigma.scope_allowed(uuid,text,text,boolean) to adlog_storage_owner;
grant select(installation_id,plugin_id,source_instance_id,rule_id,raw_sha256,canonical_sha256,
    upstream_commit,status,tags) on sli_sigma.sigma_rule_revisions to adlog_user;
create policy attack_revision_read on sli_sigma.sigma_rule_revisions for select to adlog_user
    using (sli_sigma.scope_allowed(installation_id,plugin_id,source_instance_id,false));
grant select on sli_sigma.attack_catalogs to adlog_user,adlog_sigma_reader,adlog_sigma_writer;
grant insert(stix_sha256,document_json) on sli_sigma.attack_catalogs to adlog_sigma_writer;
grant select on sli_sigma.attack_source_scopes,sli_sigma.attack_history_coverage
    to adlog_user,adlog_sigma_reader,adlog_sigma_writer;
grant insert(installation_id,plugin_id,source_instance_id,source_generation,collection_scope_id,resources)
    on sli_sigma.attack_source_scopes to adlog_sigma_writer;
grant insert(installation_id,plugin_id,source_instance_id,source_generation,collection_scope_id,
    rule_id,raw_sha256,time_from,time_to,document_json)
    on sli_sigma.attack_history_coverage to adlog_sigma_writer;

do $$ declare t text; begin
    foreach t in array array['attack_source_scopes','attack_history_coverage'] loop
        execute format('alter table sli_sigma.%I enable row level security',t);
        execute format('create policy scoped_read on sli_sigma.%I for select
            to adlog_user,adlog_sigma_reader,adlog_sigma_writer
            using (sli_sigma.scope_allowed(installation_id,plugin_id,source_instance_id,false))',t);
        execute format('create policy scoped_insert on sli_sigma.%I for insert to adlog_sigma_writer
            with check (sli_sigma.scope_allowed(installation_id,plugin_id,source_instance_id,true))',t);
    end loop;
    foreach t in array array['attack_catalogs','attack_source_scopes','attack_history_coverage'] loop
        execute format('create trigger immutable_rows before update or delete on sli_sigma.%I
            for each row execute function sli_sigma.reject_mutation()',t);
        execute format('create trigger immutable_truncate before truncate on sli_sigma.%I
            for each statement execute function sli_sigma.reject_mutation()',t);
    end loop;
end $$;
reset role;
set local role adlog_storage_owner;
-- The runtime receives aggregate EXECUTE only. The reporting function's
-- NOLOGIN owner gets exactly the three required columns, still behind RLS.
grant select(rule_id,occurred_at_utc,document_json) on public.semantic_detection_matches to adlog_sigma_owner;
create policy attack_aggregate_read on public.semantic_detection_matches for select to adlog_sigma_owner
    using (sli_sigma.scope_allowed((document_json#>>'{evidence,scope,installation_id}')::uuid,
        document_json#>>'{evidence,scope,plugin_id}',document_json#>>'{evidence,scope,source_instance_id}',false));
reset role;
set local role adlog_sigma_owner;
create function sli_sigma.read_attack_live_matches(
    p_installation uuid,p_plugin text,p_source text,p_generation text,p_collection text,
    p_since timestamptz,p_until timestamptz
) returns table(rule_id text,rule_sha256 text,manifest_sha256 text,compiler_version text,
    mapping_version text,overlay_sha256 text,evaluation_mode text,matches bigint,
    first_occurred_at timestamptz,last_occurred_at timestamptz)
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select d.rule_id,d.document_json->>'rule_sha256',d.document_json->>'manifest_sha256',
        d.document_json->>'compiler_version',d.document_json->>'mapping_version',
        d.document_json->>'overlay_sha256',d.document_json->>'evaluation_mode',count(*),
        min(d.occurred_at_utc),max(d.occurred_at_utc)
    from public.semantic_detection_matches d
    where sli_sigma.scope_allowed(p_installation,p_plugin,p_source,false)
      and p_since<p_until and p_until<=p_since+interval '31 days'
      and d.document_json#>'{evidence,scope}'=jsonb_build_object(
          'installation_id',p_installation::text,'plugin_id',p_plugin,'source_instance_id',p_source,
          'source_generation',p_generation,'collection_scope_id',p_collection)
      and d.occurred_at_utc>=p_since and d.occurred_at_utc<p_until
    group by 1,2,3,4,5,6,7 order by 1,2,3,4,5,6,7 limit 5001;
$$;
revoke all on function sli_sigma.read_attack_live_matches(uuid,text,text,text,text,timestamptz,timestamptz) from public;
grant execute on function sli_sigma.read_attack_live_matches(uuid,text,text,text,text,timestamptz,timestamptz)
    to adlog_user,adlog_sigma_reader;
reset role;
set local role adlog_storage_owner;
insert into public.schema_migrations(version,name) values(222,'sigma_attack_coverage');
commit;
