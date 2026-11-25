begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_file_servers_report416'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=415 and name='password_portion_canonical')
       or exists(select 1 from public.schema_migrations where version>=416) then
        raise exception 'file_servers_report416_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_file_audit_owner;

-- Only the existing bounded report function changes its maximum page size.
-- Keep the exact previous definition for a reversible, guarded rollback.
create table sli_plugin_file_audit.report_restore416(signature regprocedure primary key,definition text not null,installed_definition text);
revoke all on sli_plugin_file_audit.report_restore416 from public,adlog_user;
do $$ declare original text; installed text; signature regprocedure;
begin
    signature:='sli_plugin_file_audit.report_rows(jsonb,text,timestamptz,timestamptz,text,boolean,text,text,jsonb,integer)'::regprocedure;
    original:=pg_get_functiondef(signature);
    if strpos(original,'p_limit>100 or length(p_path)>4096')=0 then
        raise exception 'file_servers_report416_reader_shape' using errcode='55000';
    end if;
    installed:=replace(original,'p_limit>100 or length(p_path)>4096','p_limit>200 or length(p_path)>4096');
    execute installed;
    insert into sli_plugin_file_audit.report_restore416 values(signature,original,pg_get_functiondef(signature));
end $$;

-- This is a projection of observed objects, not an inventory or a new scan.
-- Each selected snapshot is one retained page. No page claims whole-walk coverage.
reset role;
set local role adlog_storage_owner;
create function public.read_file_audit_objects416(
    p_roots jsonb,p_snapshot uuid,p_end timestamptz,p_path text,p_nested boolean,
    p_employee text,p_operation text,p_after jsonb,p_limit integer)
returns jsonb language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare result jsonb;
begin
    if jsonb_typeof(p_roots) is distinct from 'array' or jsonb_array_length(p_roots)>1000
       or p_end is null or p_limit is null or p_limit<1 or p_limit>200
       or length(p_path)>4096 or length(p_employee)>256 then
        raise exception 'file_audit_report_parameters_invalid' using errcode='22023';
    end if;
    with roots as materialized (
        select distinct r as root from jsonb_array_elements(p_roots) r
    ), selected as materialized (
        select r.root,s.*
        from roots r cross join lateral (
            select s.* from sli_plugin_file_audit.access_snapshots s
            where s.agent_id::text=r.root->>'agent_id'
                and s.source_instance_id=r.root->>'source_instance_id'
                and s.collection_scope_id=r.root->>'collection_scope_id'
                and s.observed_at<p_end and (p_snapshot is null or s.snapshot_id=p_snapshot)
            order by s.observed_at desc,s.snapshot_id desc limit 1
        ) s
        join sli_plugin_file_audit.policy_revisions p on p.agent_id=s.agent_id
            and p.source_instance_id=s.source_instance_id and p.revision::text=s.snapshot->>'policy_revision'
        where exists(select 1 from jsonb_array_elements(p.policy->'roots') saved
            where saved->>'collection_scope_id'=s.collection_scope_id
                and lower(saved->>'path')=lower(r.root->>'path')
                and lower(coalesce(saved->>'share_name',''))=lower(coalesce(r.root->>'share_name','')))
    ), objects as materialized (
        select distinct on(s.snapshot_id,lower(o.value->>'path'))
            encode(sha256(convert_to('file-audit-object:'||s.snapshot_id::text||':'||lower(o.value->>'path'),'UTF8')),'hex') as id,
            s.observed_at,s.root||jsonb_build_object(
                'snapshot_id',s.snapshot_id,'observed_at',s.observed_at,'completeness',s.completeness,
                'unread_objects',s.unread_objects,'scan_id',s.snapshot->'scan_id',
                'page_number',s.snapshot->'page_number','inventory_has_more',s.snapshot->'has_more',
                'path',o.value->'path','object_type',o.value->'object_type',
                'owner_sid',o.value->'owner_sid','file_id',o.value->'object_id',
                'dacl_state',case when jsonb_typeof(o.value->'dacl')='string' then 'observed' else 'missing' end,
                'sacl_state',case when jsonb_typeof(o.value->'sacl')='string' then 'observed' else 'missing' end,
                'sacl_protected',o.value->'sacl_protected','record_unit','observed_object') as row
        from selected s cross join lateral jsonb_array_elements(s.snapshot->'objects') with ordinality o(value,n)
        where public.file_audit_path_in_root_v264(o.value->>'path',s.root->>'path')
            and (coalesce(p_path,'')='' or lower(o.value->>'path')=lower(p_path)
                or p_nested and public.file_audit_path_in_root_v264(o.value->>'path',p_path))
            and (coalesce(p_employee,'')='' or o.value->>'owner_sid'=p_employee
                or position(';'||p_employee||')' in coalesce(o.value->>'dacl',''))>0
                or position(';'||p_employee||')' in coalesce(s.snapshot#>>'{share,dacl}',''))>0)
            and (coalesce(p_operation,'')='' or p_operation='permissions')
        order by s.snapshot_id,lower(o.value->>'path'),o.n
    ), page as materialized (
        select * from objects where p_after->>'at' is null
            or (observed_at,id)<((p_after->>'at')::timestamptz,p_after->>'id')
        order by observed_at desc,id desc limit p_limit+1
    )
    select jsonb_build_object('service_filter_version',1,
        'items',coalesce((select jsonb_agg(row||jsonb_build_object('id',id) order by observed_at desc,id desc)
            from (select * from page order by observed_at desc,id desc limit p_limit) q),'[]'::jsonb),
        'filtered_count',(select count(*) from objects),
        'has_more',(select count(*)>p_limit from page),
        'after',(select jsonb_build_object('at',observed_at,'id',id) from page
            order by observed_at desc,id desc offset p_limit-1 limit 1),
        'snapshot_count',(select count(*) from selected),'record_unit','observed_object',
        'inventory_scope','retained_snapshot_pages') into result;
    return result;
end $$;

-- Exact tuple, historical policy root, snapshot, cutoff and path are rechecked.
-- A missing object or ACL stays missing. Only the selected object's descriptors
-- are returned; the runtime receives no direct table privileges.
create function public.read_file_audit_snapshot416(
    p_root jsonb,p_snapshot uuid,p_end timestamptz,p_path text)
returns jsonb language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare s sli_plugin_file_audit.access_snapshots%rowtype; policy jsonb; objects jsonb; result jsonb;
begin
    if jsonb_typeof(p_root) is distinct from 'object' or p_snapshot is null or p_end is null
       or p_path is null or length(p_path)>4096
       or not public.file_audit_path_in_root_v264(p_path,p_root->>'path') then
        return null;
    end if;
    select q.* into s from sli_plugin_file_audit.access_snapshots q
        where q.snapshot_id=p_snapshot and q.agent_id::text=p_root->>'agent_id'
            and q.source_instance_id=p_root->>'source_instance_id'
            and q.collection_scope_id=p_root->>'collection_scope_id' and q.observed_at<p_end;
    if not found then return null; end if;
    select p.policy into policy from sli_plugin_file_audit.policy_revisions p
        where p.agent_id=s.agent_id and p.source_instance_id=s.source_instance_id
            and p.revision::text=s.snapshot->>'policy_revision';
    if policy is null or not exists(select 1 from jsonb_array_elements(policy->'roots') saved
        where saved->>'collection_scope_id'=s.collection_scope_id
            and lower(saved->>'path')=lower(p_root->>'path')
            and lower(coalesce(saved->>'share_name',''))=lower(coalesce(p_root->>'share_name',''))) then
        return null;
    end if;
    select coalesce(jsonb_agg(o),'[]'::jsonb) into objects
        from jsonb_array_elements(s.snapshot->'objects') o where lower(o->>'path')=lower(p_path);
    result:=jsonb_build_object(
        'root',p_root,'policy',policy,
        'snapshot',jsonb_build_object('id',s.snapshot_id,'observed_at',s.observed_at,
            'policy_revision',s.snapshot->'policy_revision','scan_id',s.snapshot->'scan_id',
            'page_number',s.snapshot->'page_number','has_more',s.snapshot->'has_more',
            'completeness',s.completeness,'unread_objects',s.unread_objects,
            'source_instance_id',s.source_instance_id,'source_generation',s.snapshot->'source_generation',
            'snapshot_sha256',s.snapshot_sha256),
        'share',s.snapshot->'share',
        'object',case when jsonb_array_length(objects)=1 then objects->0 end,
        'object_state',case when jsonb_array_length(objects)=1 then 'observed'
            when jsonb_array_length(objects)=0 then 'not_observed' else 'ambiguous' end);
    with history as materialized (
        select h.snapshot_id,h.observed_at,h.completeness,h.unread_objects,
            h.snapshot->'policy_revision' as revision,h.snapshot->'scan_id' as scan_id,
            h.snapshot->'page_number' as page_number,h.snapshot->'has_more' as has_more
        from sli_plugin_file_audit.access_snapshots h
        join sli_plugin_file_audit.policy_revisions p on p.agent_id=h.agent_id
            and p.source_instance_id=h.source_instance_id and p.revision::text=h.snapshot->>'policy_revision'
        where h.agent_id=s.agent_id and h.source_instance_id=s.source_instance_id
            and h.collection_scope_id=s.collection_scope_id and h.observed_at<p_end
            and exists(select 1 from jsonb_array_elements(p.policy->'roots') saved
                where saved->>'collection_scope_id'=h.collection_scope_id
                    and lower(saved->>'path')=lower(p_root->>'path')
                    and lower(coalesce(saved->>'share_name',''))=lower(coalesce(p_root->>'share_name','')))
        order by h.observed_at desc,h.snapshot_id desc limit 201
    ) select result||jsonb_build_object(
        'snapshots',coalesce((select jsonb_agg(jsonb_build_object('id',snapshot_id,'observed_at',observed_at,
            'policy_revision',revision,'scan_id',scan_id,'page_number',page_number,'has_more',has_more,
            'completeness',completeness,'unread_objects',unread_objects) order by observed_at desc,snapshot_id desc)
            from (select * from history order by observed_at desc,snapshot_id desc limit 200) q),'[]'::jsonb),
        'snapshots_has_more',(select count(*)>200 from history)) into result;
    select result||jsonb_build_object('objects',coalesce(jsonb_agg(jsonb_build_object(
        'id',encode(sha256(convert_to('file-audit-object:'||s.snapshot_id::text||':'||lower(o->>'path'),'UTF8')),'hex'),
        'path',o->'path','object_type',o->'object_type','owner_sid',o->'owner_sid',
        'file_id',o->'object_id','snapshot_id',s.snapshot_id) order by lower(o->>'path')),'[]'::jsonb),
        'objects_has_more',jsonb_array_length(s.snapshot->'objects')>200) into result
        from (select o from jsonb_array_elements(s.snapshot->'objects') o
            where public.file_audit_path_in_root_v264(o->>'path',p_root->>'path')
            order by lower(o->>'path') limit 200) q;
    return result;
end $$;
revoke all on function public.read_file_audit_objects416(jsonb,uuid,timestamptz,text,boolean,text,text,jsonb,integer) from public;
revoke all on function public.read_file_audit_snapshot416(jsonb,uuid,timestamptz,text) from public;
grant execute on function public.read_file_audit_objects416(jsonb,uuid,timestamptz,text,boolean,text,text,jsonb,integer),
    public.read_file_audit_snapshot416(jsonb,uuid,timestamptz,text) to adlog_user;
insert into public.schema_migrations(version,name) values(416,'file_servers_report_projection');
reset role;
commit;
