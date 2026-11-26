begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_file_audit_scope_inventory422'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=418 and name='password_threshold_rules')
       or exists(select 1 from public.schema_migrations where version>=422) then
        raise exception 'file_audit_scope_inventory422_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

-- Scope inventory is independent of the interactive share discovery request and its expiry.
alter table public.sli_file_audit_smb_catalog
    add column inventory_revision bigint,
    add column scope_inventory jsonb not null default '{}'::jsonb,
    add constraint file_audit_scope_inventory422_check check (
        (inventory_revision is null)=(scope_inventory='{}'::jsonb)
        and (inventory_revision is null or inventory_revision between 1 and 9007199254740991)
        and jsonb_typeof(scope_inventory)='object' and octet_length(scope_inventory::text)<=8388608);

-- The discovery endpoint keeps its original access. Share DACLs have the snapshot read boundary.
revoke select,insert,update on public.sli_file_audit_smb_catalog from adlog_user;
grant select(agent_id,source_id,supported_until,request_id,expires_at,result_status,native_status,shares),
      insert(agent_id,source_id,supported_until),
      update(source_id,supported_until,request_id,expires_at,result_status,native_status,shares)
    on public.sli_file_audit_smb_catalog to adlog_user;

create function public.clear_file_audit_catalog_source422()
returns trigger language plpgsql set search_path=pg_catalog,pg_temp as $$
begin
    new.inventory_revision:=null;
    new.scope_inventory:='{}'::jsonb;
    return new;
end $$;
revoke all on function public.clear_file_audit_catalog_source422() from public;
create trigger file_audit_catalog_source422 before update of source_id on public.sli_file_audit_smb_catalog
    for each row when (old.source_id is distinct from new.source_id)
    execute function public.clear_file_audit_catalog_source422();

create function public.register_file_audit_source422(p_agent uuid,p_source text)
returns void language sql set search_path=pg_catalog,pg_temp as $$
    insert into public.acquisition_source_instances as source
        (source_instance_id,organization_scope,source_kind,endpoint_identity,adapter_binding,display_name,configuration_sha256)
    select p_source,'platform','sli.file-audit.server',p_source,'sli.file-audit',host.name,
        encode(sha256(convert_to('sli.file-audit:'||p_source,'UTF8')),'hex')
    from public.sli_agents a
    left join public.sli_agent_module_bindings dc on dc.agent_id=a.id and dc.module_id='sli.windows.ad-dc'
    cross join lateral (values(coalesce(a.registration_host_name,dc.source_name))) host(name)
    where a.id=p_agent and a.status='active' and coalesce(a.source_host_id,a.host_id)::text=p_source
        and length(host.name) between 1 and 253 and host.name ~ '^[A-Za-z0-9][A-Za-z0-9.-]*$'
    on conflict (source_instance_id) do update set display_name=excluded.display_name,updated_at=clock_timestamp()
    where source.source_kind=excluded.source_kind and source.adapter_binding=excluded.adapter_binding
        and source.organization_scope=excluded.organization_scope and source.endpoint_identity=excluded.endpoint_identity
        and source.display_name is distinct from excluded.display_name
$$;
revoke all on function public.register_file_audit_source422(uuid,text) from public;

create function public.register_file_audit_policy_source422()
returns trigger language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    if coalesce(new.policy->>'source_kind','server')='server' then
        perform public.register_file_audit_source422(new.agent_id,new.source_instance_id);
    end if;
    return null;
end $$;
revoke all on function public.register_file_audit_policy_source422() from public;
grant execute on function public.register_file_audit_policy_source422() to adlog_file_audit_owner;

create function public.store_file_audit_catalog_inventory422()
returns trigger language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare
    share jsonb := new.snapshot->'share';
    revision bigint;
    inventory jsonb;
begin
    if new.completeness='failed' or (share @> '{"complete":true}') is not true
       or jsonb_typeof(share->'dacl') is distinct from 'string' or length(share->>'dacl')>65536
       or coalesce(length(share->>'name'),0) not between 1 and 80
       or coalesce(length(share->>'path'),0) not between 3 and 4096
       or length(new.collection_scope_id) not between 1 and 256
       or new.collection_scope_id !~ '^[A-Za-z0-9_.:-]+$' then
        return null;
    end if;
    select p.revision into revision
    from public.sli_agents a join sli_plugin_file_audit.policy_revisions p
        on p.agent_id=a.id and p.source_instance_id=new.source_instance_id
        and p.revision::text=new.snapshot->>'policy_revision'
    where a.id=new.agent_id and a.status='active' and coalesce(a.source_host_id,a.host_id)::text=new.source_instance_id
        and a.file_audit#>>'{request,command,policy_revision}'=p.revision::text
        and coalesce(p.policy->>'source_kind','server')='server'
        and exists(select 1 from jsonb_array_elements(p.policy->'roots') root
            where root->>'collection_scope_id'=new.collection_scope_id
                and root->>'share_name'=share->>'name' and root->>'path'=share->>'path');
    if not found then return null; end if;

    inventory:=jsonb_build_object(new.collection_scope_id,jsonb_build_object(
        'share_name',share->'name','path',share->'path','dacl',share->'dacl','observed_at',new.observed_at));
    insert into public.sli_file_audit_smb_catalog as catalog (agent_id,source_id,supported_until)
    values(new.agent_id,new.source_instance_id,'-infinity')
    on conflict (agent_id) do update set
        source_id=excluded.source_id,supported_until=excluded.supported_until,
        request_id=null,expires_at=null,result_status=null,native_status=null,shares=excluded.shares
    where catalog.source_id<>excluded.source_id;
    update public.sli_file_audit_smb_catalog catalog set
        inventory_revision=revision,
        scope_inventory=case when catalog.inventory_revision=revision
            then catalog.scope_inventory||inventory else inventory end
    where catalog.agent_id=new.agent_id and catalog.source_id=new.source_instance_id
        and (catalog.inventory_revision is null or catalog.inventory_revision<revision
        or (catalog.inventory_revision=revision
            and (catalog.scope_inventory->new.collection_scope_id is null
                or (catalog.scope_inventory->new.collection_scope_id->>'observed_at')::timestamptz<new.observed_at)));
    return null;
end $$;
revoke all on function public.store_file_audit_catalog_inventory422() from public;
grant execute on function public.store_file_audit_catalog_inventory422() to adlog_file_audit_owner;

grant select(source_instance_id,source_kind,display_name) on public.acquisition_source_instances to adlog_file_audit_owner;
select public.register_file_audit_source422(p.agent_id,p.source_instance_id)
from (select distinct on(agent_id,source_instance_id) agent_id,source_instance_id,policy
      from sli_plugin_file_audit.policy_revisions order by agent_id,source_instance_id,revision desc) p
where coalesce(p.policy->>'source_kind','server')='server';

reset role;
set local role adlog_file_audit_owner;
create trigger file_audit_policy_source422 after insert on sli_plugin_file_audit.policy_revisions
    for each row execute function public.register_file_audit_policy_source422();
create trigger file_audit_catalog_inventory422 after insert on sli_plugin_file_audit.access_snapshots
    for each row execute function public.store_file_audit_catalog_inventory422();

create or replace function sli_plugin_file_audit.report_roots()
returns jsonb language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select coalesce(jsonb_agg(q.root order by q.agent_id,q.source_instance_id,q.scope_id),'[]'::jsonb)
    from (
        select p.agent_id,p.source_instance_id,r->>'collection_scope_id' as scope_id,
            r||jsonb_build_object('agent_id',p.agent_id,'source_instance_id',p.source_instance_id,
                'source_name',coalesce(source.display_name,p.policy->>'source_name',p.source_instance_id),
                'source_kind',coalesce(p.policy->>'source_kind','server'),'policy_revision',p.revision) as root
        from (select distinct on(agent_id,source_instance_id) *
              from sli_plugin_file_audit.policy_revisions order by agent_id,source_instance_id,revision desc) p
        left join public.acquisition_source_instances source on source.source_instance_id=p.source_instance_id
            and source.source_kind='sli.file-audit.server' and coalesce(p.policy->>'source_kind','server')='server'
        cross join lateral jsonb_array_elements(p.policy->'roots') r
        order by p.agent_id,p.source_instance_id,r->>'collection_scope_id' limit 1001
    ) q
$$;
reset role;
insert into public.schema_migrations(version,name) values(422,'file_audit_scope_inventory');
commit;
