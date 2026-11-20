-- W01: account watch configuration only; no event processing or notifications.
begin;
select pg_advisory_xact_lock(hashtext('sli_watch_registry_v249'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=248 and name='entity_context_history_reads')
       or exists(select 1 from public.schema_migrations where version>=249) then
        raise exception 'migration 249 prerequisites failed';
    end if;
end $$;
set local role adlog_storage_owner;
create table public.watch_entry_versions (
    id uuid not null,
    revision bigint not null check(revision>0),
    identity jsonb not null check(jsonb_typeof(identity)='object' and octet_length(identity::text)<=8192),
    entity_id bigint not null check(entity_id>0),
    plugin_id text not null default 'sli.ad' check(plugin_id='sli.ad'),
    collection_scope_id text not null,
    owner text not null check(length(owner) between 1 and 128),
    reason text not null check(length(reason) between 1 and 500),
    active boolean not null,
    active_from timestamptz not null,
    expires_at timestamptz not null,
    valid_from timestamptz not null,
    valid_to timestamptz check(valid_to>=valid_from),
    actor_type text not null check(actor_type in ('session','api_key')),
    actor_id bigint not null check(actor_id>0),
    primary key(id,revision),
    check(not active or expires_at>active_from),
    check(coalesce(identity ?& array['domain_id','entity_id','sid','guid']
        and entity_id=(identity->>'entity_id')::bigint and (identity->>'domain_id')::bigint>0
        and collection_scope_id='ad-domain:'||(identity->>'domain_id')
        and identity->>'sid' ~ '^S-1-[0-9]+(-[0-9]+)+$'
        and (identity->>'guid')::uuid is not null,false))
);
create unique index watch_current_version on public.watch_entry_versions(id) where valid_to is null;
create unique index watch_current_account on public.watch_entry_versions(entity_id) where valid_to is null;
create index watch_scope on public.watch_entry_versions(collection_scope_id,entity_id);
create function public.guard_watch_interval() returns trigger language plpgsql
set search_path=pg_catalog,pg_temp as $$ begin
    if old.valid_to is not null or new.valid_to is null then
        raise exception 'watch_interval_immutable';
    end if;
    return new;
end $$;
revoke all on function public.guard_watch_interval() from public;
create trigger watch_interval_immutable before update on public.watch_entry_versions
for each row execute function public.guard_watch_interval();
revoke all on public.watch_entry_versions from public,adlog_user;
grant select,insert on public.watch_entry_versions to adlog_user;
grant update(valid_to) on public.watch_entry_versions to adlog_user;
reset role;
insert into public.access_capabilities(capability_key,label,description)
values('watch.manage','Manage account watch','Start, extend and stop account watch in an assigned scope');
insert into public.access_package_capabilities(package_id,capability_id)
select p.id,c.id from public.access_packages p cross join public.access_capabilities c
where p.package_key='access_admin' and c.capability_key='watch.manage';
insert into public.report_datasets_v4(dataset_key,version,name,object_type,fields_json,filters_json,actions_json,status)
values('watch.registry',1,'Account watch','watch_entry',
    '[{"key":"identity","category":"identity_basic"},{"key":"reason","category":"security"}]'::jsonb,
    '[]'::jsonb,'["view","manage_watch"]'::jsonb,'published');
insert into public.report_registry_v4(report_key,version,name,owner_name,purpose,dataset_id,
    definition_json,sensitivity,status,published_at)
select 'watch.registry',1,'Account watch','SLI','Revisioned account watch with reason and expiry',id,
    '{"target_path":"/platform-settings#watch","field_categories":["identity_basic","security"],
      "actions":["view","manage_watch"],"export_policy":"denied"}'::jsonb,'restricted','published',now()
from public.report_datasets_v4 where dataset_key='watch.registry' and version=1;
insert into public.access_package_reports(package_id,report_key,field_categories,allowed_actions,scope_json)
select id,'watch.registry',array['identity_basic','security'],array['view','manage_watch'],'{"kind":"all"}'::jsonb
from public.access_packages where package_key='access_admin';
insert into public.schema_migrations(version,name) values(249,'watch_registry');
commit;
