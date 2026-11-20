-- T019: exact-revision editorial labels only; no event or raw rule access.
begin;
select pg_advisory_xact_lock(hashtext('sli_sigma_rule_labels_v286'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=285 and name='report_producer')
       or exists(select 1 from public.schema_migrations where version>=286)
       or to_regprocedure('sli_sigma.read_rule_labels(uuid,text,text,uuid,text)') is not null then
        raise exception 'migration 286 prerequisites failed';
    end if;
end $$;
set local lock_timeout='5s';
set local role adlog_sigma_owner;
create function sli_sigma.read_rule_labels(
    p_installation uuid,p_plugin text,p_source text,p_rule uuid,p_raw_sha256 text
) returns table(rule_id uuid,raw_sha256 text,title text,description text)
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select r.rule_id,r.raw_sha256,
        case when jsonb_typeof(r.canonical_rule->'title')='string'
            and length(r.canonical_rule->>'title') between 1 and 512
            then r.canonical_rule->>'title' end,
        case when jsonb_typeof(r.canonical_rule->'description')='string'
            and length(r.canonical_rule->>'description') between 1 and 4000
            then r.canonical_rule->>'description' end
    from sli_sigma.sigma_rule_revisions r
    where sli_sigma.scope_allowed(p_installation,p_plugin,p_source,false)
      and r.installation_id=p_installation and r.plugin_id=p_plugin and r.source_instance_id=p_source
      and r.rule_id=p_rule and r.raw_sha256=p_raw_sha256
    limit 1
$$;
revoke all on function sli_sigma.read_rule_labels(uuid,text,text,uuid,text) from public;
grant execute on function sli_sigma.read_rule_labels(uuid,text,text,uuid,text) to adlog_user;
reset role;
set local role adlog_storage_owner;
insert into public.schema_migrations(version,name) values(286,'sigma_rule_labels');
commit;
