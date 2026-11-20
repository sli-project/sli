-- D01: existing-object labels only. No detector, source activation or audit writes.
begin;
select pg_advisory_xact_lock(hashtext('sli_decoy_registry_v243'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=242 and name='gpo_plan_credentials')
       or exists(select 1 from public.schema_migrations where version>=243) then
        raise exception 'migration 243 prerequisites failed';
    end if;
end $$;
set local role adlog_storage_owner;
create table public.decoy_label_versions (
    id uuid not null,
    revision bigint not null check(revision>0),
    kind text not null check(kind in ('account','file')),
    identity jsonb not null check(jsonb_typeof(identity)='object' and octet_length(identity::text)<=8192),
    owner text not null check(length(owner) between 1 and 128),
    reason text not null check(length(reason) between 1 and 500),
    active boolean not null,
    active_from timestamptz not null,
    active_to timestamptz check(active_to>=active_from),
    actor_type text not null check(actor_type in ('session','api_key')),
    actor_id bigint not null check(actor_id>0),
    readiness jsonb not null check(coalesce(jsonb_typeof(readiness)='object' and readiness->>'state' in ('ready','not_ready'),false)),
    plugin_id text not null,
    source_instance_id text,
    device_id text,
    entity_id bigint,
    collection_scope_id text not null,
    primary key(id,revision),
    check(coalesce((kind='account' and plugin_id='sli.ad' and entity_id>0
            and identity ?& array['domain_id','entity_id','sid','guid']
            and entity_id=(identity->>'entity_id')::bigint
            and collection_scope_id='ad-domain:'||(identity->>'domain_id')
            and source_instance_id is null and device_id is null)
       or (kind='file' and plugin_id='sli.file-audit' and entity_id is null
            and identity ?& array['agent_id','source_instance_id','collection_scope_id','path']
            and device_id=identity->>'agent_id' and source_instance_id=identity->>'source_instance_id'
            and collection_scope_id=identity->>'collection_scope_id'),false))
);
create unique index decoy_current_version on public.decoy_label_versions(id) where active_to is null;
create unique index decoy_active_identity on public.decoy_label_versions(kind,identity) where active and active_to is null;
create index decoy_scope on public.decoy_label_versions(collection_scope_id,source_instance_id,device_id);
create function public.guard_decoy_label_interval() returns trigger language plpgsql
set search_path=pg_catalog,pg_temp as $$ begin
    if old.active_to is not null or new.active_to is null then
        raise exception 'decoy_interval_immutable';
    end if;
    return new;
end $$;
revoke all on function public.guard_decoy_label_interval() from public;
create trigger decoy_interval_immutable before update on public.decoy_label_versions
for each row execute function public.guard_decoy_label_interval();
revoke all on public.decoy_label_versions from public,adlog_user;
grant select,insert on public.decoy_label_versions to adlog_user;
grant update(active_to) on public.decoy_label_versions to adlog_user;
reset role;
set local role adlog_file_audit_owner;
-- A bounded exact-path check, with no inventory or underlying table read grant.
create function sli_plugin_file_audit.decoy_file_present(
    p_agent uuid,p_source text,p_scope text,p_path text,p_revision text
) returns boolean language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    with latest as (
        select s.snapshot->>'scan_id' as scan_id from sli_plugin_file_audit.access_snapshots s
        where s.agent_id=p_agent and s.source_instance_id=p_source and s.collection_scope_id=p_scope
          and s.snapshot->>'policy_revision'=p_revision and s.observed_at between now()-interval '1 day' and now()
        order by s.observed_at desc,s.snapshot_id desc limit 1
    )
    select coalesce((select not coalesce((o->>'sacl_missing')::boolean,true)
                             and not coalesce((o->>'sacl_protected')::boolean,true)
        from sli_plugin_file_audit.access_snapshots s
        cross join lateral jsonb_array_elements(s.snapshot->'objects') o
        where s.agent_id=p_agent and s.source_instance_id=p_source and s.collection_scope_id=p_scope
          and s.snapshot->>'policy_revision'=p_revision and s.observed_at between now()-interval '1 day' and now()
          and s.snapshot->>'scan_id'=(select scan_id from latest)
          and lower(replace(o->>'path','/','\'))=p_path and o->>'object_type'='file'
        order by s.observed_at desc,s.snapshot_id desc limit 1),false);
$$;
revoke all on function sli_plugin_file_audit.decoy_file_present(uuid,text,text,text,text) from public;
grant execute on function sli_plugin_file_audit.decoy_file_present(uuid,text,text,text,text) to adlog_user;
reset role;
insert into public.access_capabilities(capability_key,label,description)
values('decoys.manage','Manage decoy labels','Register, disable and revise labels in an assigned scope');
insert into public.access_package_capabilities(package_id,capability_id)
select p.id,c.id from public.access_packages p cross join public.access_capabilities c
where p.package_key='access_admin' and c.capability_key='decoys.manage';
insert into public.report_datasets_v4(dataset_key,version,name,object_type,fields_json,filters_json,actions_json,status)
values('decoys.registry',1,'Decoy registry','decoy_label',
    '[{"key":"identity","category":"identity_basic"},{"key":"reason","category":"security"},
      {"key":"readiness","category":"technical"}]'::jsonb,'[]'::jsonb,'["view","manage_decoy"]'::jsonb,'published');
insert into public.report_registry_v4(report_key,version,name,owner_name,purpose,dataset_id,
    definition_json,sensitivity,status,published_at)
select 'decoys.registry',1,'Decoy registry','SLI','Existing-object labels and audit readiness',id,
    '{"target_path":"/platform-settings#decoys","field_categories":["identity_basic","security","technical"],
      "actions":["view","manage_decoy"],"export_policy":"denied"}'::jsonb,'restricted','published',now()
from public.report_datasets_v4 where dataset_key='decoys.registry' and version=1;
insert into public.access_package_reports(package_id,report_key,field_categories,allowed_actions,scope_json)
select id,'decoys.registry',array['identity_basic','security','technical'],array['view','manage_decoy'],'{"kind":"all"}'::jsonb
from public.access_packages where package_key='access_admin';
insert into public.schema_migrations(version,name) values(243,'decoy_registry');
commit;
