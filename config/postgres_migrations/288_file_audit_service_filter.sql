-- T070: exclude only SYSTEM access checks from report results by default.
-- The existing cursor JSON carries show_service alongside optional at/id keys.
-- A failed transaction restores the previous function and its ACL. After commit,
-- recover using a coordinated application/database backup or a forward repair;
-- the new application requires the function's service_filter_version marker.
begin;
select pg_advisory_xact_lock(hashtext('sli_file_audit_service_filter_v288'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=286 and name='sigma_rule_labels')
       or not exists(select 1 from public.schema_migrations where version=287 and name='workstation_inventory_job')
       or exists(select 1 from public.schema_migrations where version>=288)
       or not exists(select 1 from pg_catalog.pg_proc where
           oid=to_regprocedure('sli_plugin_file_audit.report_rows(jsonb,text,timestamptz,timestamptz,text,boolean,text,text,jsonb,integer)')
           and proowner=(select oid from pg_catalog.pg_roles where rolname='adlog_file_audit_owner')) then
        raise exception 'migration 288 prerequisites failed';
    end if;
end $$;
set local role adlog_file_audit_owner;
create or replace function sli_plugin_file_audit.report_rows(p_roots jsonb,p_tab text,p_start timestamptz,p_end timestamptz,
    p_path text,p_nested boolean,p_employee text,p_operation text,p_after jsonb,p_limit integer)
returns jsonb language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare v_result jsonb;
begin
    if jsonb_typeof(p_roots) is distinct from 'array' or jsonb_array_length(p_roots)>1000
       or p_tab not in ('overview','actions','mass-operations','permission-changes','access-denials',
                       'out-of-hours','permissions','audit-state')
       or p_start is null or p_end is null or p_end<=p_start or p_end-p_start>interval '31 days'
       or p_limit is null or p_limit<1 or p_limit>100 or length(p_path)>4096 or length(p_employee)>256 then
        raise exception 'file_audit_report_parameters_invalid';
    end if;

    -- Action pages do not need snapshots, rules or JSON serialization of the
    -- complete window. Keep typed filters/counts and enrich only the page.
    if p_tab in ('actions','access-denials','permission-changes') then
        with roots as materialized (
            select distinct agent_id,source_instance_id,collection_scope_id
            from jsonb_to_recordset(p_roots) r(agent_id uuid,source_instance_id text,collection_scope_id text)
        ), filtered as materialized (
            select a.* from sli_plugin_file_audit.actions a join roots r
                using(agent_id,source_instance_id,collection_scope_id)
            where a.observed_at>=p_start and a.observed_at<p_end
              and (coalesce(p_path,'')='' or lower(a.path)=lower(p_path) or p_nested and
                left(lower(a.path),length(rtrim(lower(p_path),E'\\'))+1)=rtrim(lower(p_path),E'\\')||E'\\')
              and (coalesce(p_employee,'')='' or a.subject_sid=p_employee)
              and (coalesce(p_operation,'')='' or a.operation=p_operation)
          and (coalesce(p_after->'show_service' = 'true'::jsonb,false)
              or (a.subject_sid='S-1-5-18' and a.operation='access_check') is not true)
              and (p_tab='actions' or p_tab='access-denials' and a.outcome='failure'
                or p_tab='permission-changes' and a.operation in ('permissions','share_change','audit_change'))
        ), page as materialized (
            select * from filtered where p_after->>'at' is null or
                (observed_at,action_id)<((p_after->>'at')::timestamptz,p_after->>'id')
            order by observed_at desc,action_id desc limit p_limit+1
        )
        select jsonb_build_object('service_filter_version',1,'items',coalesce((select jsonb_agg(
                to_jsonb(q)||jsonb_build_object('id',q.action_id,'evidence',(
                    select coalesce(jsonb_agg(jsonb_build_object(
                        'reference',e.core_evidence_ref,'event_id',o.event_id,'record_id',o.record_id,
                        'generation',o.generation,'role',e.role,'payload_sha256',o.payload_sha256,
                        'path',o.normalized->>'path') order by e.core_evidence_ref),'[]'::jsonb)
                    from sli_plugin_file_audit.action_evidence e
                    left join sli_plugin_file_audit.observations o on o.evidence_key=e.evidence_key
                    where e.action_id=q.action_id)) order by q.observed_at desc,q.action_id desc)
                from (select * from page order by observed_at desc,action_id desc limit p_limit) q),'[]'::jsonb),
            'filtered_count',(select count(*) from filtered),
            'has_more',(select count(*)>p_limit from page),
            'after',(select jsonb_build_object('at',observed_at,'id',action_id) from page
                order by observed_at desc,action_id desc offset p_limit-1 limit 1)) into v_result;
        return v_result;
    end if;

    with roots as materialized (
        select * from jsonb_to_recordset(p_roots) as r(agent_id uuid,source_instance_id text,
            collection_scope_id text,path text,share_name text,source_name text,important boolean,policy_revision bigint)
    ), scoped_actions as materialized (
        select a.* from sli_plugin_file_audit.actions a join roots r
          using(agent_id,source_instance_id,collection_scope_id)
        where a.observed_at>=p_start and a.observed_at<p_end
          and (coalesce(p_path,'')='' or lower(a.path)=lower(p_path) or p_nested and
            left(lower(a.path),length(rtrim(lower(p_path),E'\\'))+1)=rtrim(lower(p_path),E'\\')||E'\\')
          and (coalesce(p_employee,'')='' or a.subject_sid=p_employee)
          and (coalesce(p_operation,'')='' or a.operation=p_operation)
          and (coalesce(p_after->'show_service' = 'true'::jsonb,false)
              or (a.subject_sid='S-1-5-18' and a.operation='access_check') is not true)
    ), latest_snapshots as materialized (
        select distinct on(s.agent_id,s.source_instance_id,s.collection_scope_id) s.*
        from sli_plugin_file_audit.access_snapshots s join roots r using(agent_id,source_instance_id,collection_scope_id)
        where s.observed_at<p_end
        order by s.agent_id,s.source_instance_id,s.collection_scope_id,s.observed_at desc,s.snapshot_id desc
    ), latest_receipts as materialized (
        select distinct on(c.agent_id,c.source_instance_id,c.collection_scope_id) c.*
        from sli_plugin_file_audit.audit_receipts c join roots r using(agent_id,source_instance_id,collection_scope_id)
        where c.observed_at<p_end
        order by c.agent_id,c.source_instance_id,c.collection_scope_id,c.observed_at desc,c.receipt_id desc
    ), candidates as materialized (
        select a.action_id as id,a.observed_at,to_jsonb(a)||jsonb_build_object('id',a.action_id) as row
        from scoped_actions a
        where p_tab='actions' or p_tab='access-denials' and a.outcome='failure'
           or p_tab='permission-changes' and a.operation in ('permissions','share_change','audit_change')
        union all
        select f.result_id,f.observed_at,f.result||jsonb_build_object('id',f.result_id,
            'evidence',(select coalesce(jsonb_agg(to_jsonb(a)||jsonb_build_object(
                'reference',ae.core_evidence_ref,'event_id',o.event_id,'record_id',o.record_id,
                'generation',o.generation,'payload_sha256',o.payload_sha256)
                order by a.observed_at,a.action_id,ae.core_evidence_ref),'[]'::jsonb)
                from sli_plugin_file_audit.rule_actions e join scoped_actions a using(action_id)
                left join sli_plugin_file_audit.action_evidence ae using(action_id)
                left join sli_plugin_file_audit.observations o on o.evidence_key=ae.evidence_key
                where e.result_id=f.result_id))
        from sli_plugin_file_audit.rule_results f join roots r using(agent_id,source_instance_id,collection_scope_id)
        where f.observed_at>=p_start and f.observed_at<p_end and (
            p_tab='mass-operations' and f.rule_code in ('file-audit.mass-read','file-audit.mass-write','file-audit.mass-delete')
            or p_tab='out-of-hours' and f.rule_code='file-audit.out-of-hours')
        union all
        select f.result_id,f.observed_at,f.result||jsonb_build_object('id',f.result_id,
            'path',f.result->'details'->>'path','snapshot_id',s.snapshot_id,'completeness',s.completeness,
            'snapshot_sha256',s.snapshot_sha256)
        from sli_plugin_file_audit.rule_results f join sli_plugin_file_audit.rule_snapshots e using(result_id)
          join latest_snapshots s using(snapshot_id)
        where p_tab='permissions'
          and f.rule_code in ('file-audit.broad-write','file-audit.direct-user-rights','file-audit.disabled-account-rights','file-audit.acl-review')
          and f.agent_id=s.agent_id and f.source_instance_id=s.source_instance_id and f.collection_scope_id=s.collection_scope_id
        union all
        select r.agent_id::text||':'||r.source_instance_id||':'||r.collection_scope_id,
            coalesce(s.observed_at,'1970-01-01'::timestamptz),to_jsonb(r)||jsonb_build_object(
                'id',r.agent_id::text||':'||r.source_instance_id||':'||r.collection_scope_id,
                'observed_at',s.observed_at,'completeness',s.completeness,'snapshot_id',s.snapshot_id,
                'objects',jsonb_array_length(s.snapshot->'objects'),'unread_objects',s.unread_objects,
                'folders_with_read_audit',case when r.important and s.completeness='complete'
                    and c.state='verified' and c.policy_revision=r.policy_revision then
                    (select count(*) from jsonb_array_elements(s.snapshot->'objects') o
                     where o->>'object_type'='directory' and o->>'sacl_missing'='false'
                       and o->>'sacl_protected'='false') else null end,
                'actions',(select count(*) from scoped_actions a where a.agent_id=r.agent_id
                    and a.source_instance_id=r.source_instance_id and a.collection_scope_id=r.collection_scope_id),
                'audit_state',c.state,'audit_receipt',to_jsonb(c),
                'delivery_received_at',d.received_at,'delivery_imported_at',d.imported_at,
                'delivery_record_id',d.record_id)
        from roots r left join latest_snapshots s using(agent_id,source_instance_id,collection_scope_id)
            left join latest_receipts c using(agent_id,source_instance_id,collection_scope_id)
        left join lateral (
            select receipt.received_at,inbox.imported_at,
                (nullif(receipt.envelope->'cursor_after'->>'token','')::jsonb->>'record_id')::bigint as record_id
            from public.sli_agent_receipts receipt
            left join public.sli_agent_packet_inbox inbox using(packet_id)
            where receipt.agent_id=r.agent_id and receipt.module_id='sli.file-audit'
              and receipt.envelope->>'source_instance_id'=r.source_instance_id
            order by receipt.sequence desc limit 1
        ) d on p_tab='audit-state'
        where p_tab in ('overview','audit-state')
    ), filtered as materialized (
        select c.* from candidates c where
          (coalesce(p_path,'')='' or p_tab in ('overview','audit-state') and
            (lower(c.row->>'path')=lower(p_path) or left(lower(p_path),length(rtrim(lower(c.row->>'path'),E'\\'))+1)=rtrim(lower(c.row->>'path'),E'\\')||E'\\')
            or lower(c.row->>'path')=lower(p_path)
            or p_nested and left(lower(c.row->>'path'),length(rtrim(lower(p_path),E'\\'))+1)=rtrim(lower(p_path),E'\\')||E'\\'
            or exists(select 1 from jsonb_array_elements(coalesce(c.row->'evidence','[]'::jsonb)) e
                where lower(e->>'path')=lower(p_path) or p_nested and
                    left(lower(e->>'path'),length(rtrim(lower(p_path),E'\\'))+1)=rtrim(lower(p_path),E'\\')||E'\\'))
          and (coalesce(p_employee,'')='' or c.row->>'subject_sid'=p_employee)
          and (coalesce(p_operation,'')='' or c.row->>'operation'=p_operation or c.row->'details'->>'operation'=p_operation
            or p_tab='mass-operations' and c.row->>'rule_code'='file-audit.mass-'||p_operation)
    ), page as (
        select * from filtered where p_after->>'at' is null or
            (observed_at,id)<((p_after->>'at')::timestamptz,p_after->>'id')
        order by observed_at desc,id desc limit p_limit+1
    )
    -- Evidence is not used to filter action rows. Load it only for the final
    -- page, preserving exact totals without random HDD reads for the window.
    select jsonb_build_object('service_filter_version',1,'items',coalesce((select jsonb_agg(
            case when p_tab in ('actions','access-denials','permission-changes') then
                row||jsonb_build_object('evidence',(select coalesce(jsonb_agg(jsonb_build_object(
                    'reference',e.core_evidence_ref,'event_id',o.event_id,'record_id',o.record_id,
                    'generation',o.generation,'role',e.role,'payload_sha256',o.payload_sha256)
                    order by e.core_evidence_ref),'[]'::jsonb)
                    from sli_plugin_file_audit.action_evidence e left join sli_plugin_file_audit.observations o
                      on o.evidence_key=e.evidence_key where e.action_id=q.id))
            else row end order by observed_at desc,id desc)
            from (select * from page order by observed_at desc,id desc limit p_limit) q),'[]'::jsonb),
        'filtered_count',(select count(*) from filtered),'has_more',(select count(*)>p_limit from page),
        'after',(select jsonb_build_object('at',observed_at,'id',id) from page
                 order by observed_at desc,id desc offset p_limit-1 limit 1),
        'summary',jsonb_build_object('read',(select count(*) from scoped_actions where operation='read'),
            'write',(select count(*) from scoped_actions where operation='write'),
            'delete',(select count(*) from scoped_actions where operation='delete'),
            'denials',(select count(*) from scoped_actions where outcome='failure')),
        'timeline',coalesce((select jsonb_agg(to_jsonb(q) order by q.at) from (
            select date_trunc('hour',observed_at) as at,count(*) as actions
            from scoped_actions group by date_trunc('hour',observed_at)) q),'[]'::jsonb),
        'inventory',case when p_tab='permissions' then coalesce((select jsonb_agg(jsonb_build_object(
            'agent_id',r.agent_id,'source_instance_id',r.source_instance_id,'collection_scope_id',r.collection_scope_id,
            'share_label',r.source_name||' · '||r.share_name,'observed_at',s.observed_at,
            'share_dacl',s.snapshot->'share'->>'dacl','share_complete',s.snapshot->'share'->'complete',
            'root_dacl',(select o->>'dacl' from jsonb_array_elements(s.snapshot->'objects') o
                where lower(o->>'path')=lower(r.path) limit 1),
            'group_sids',(select coalesce(jsonb_agg(g->>'group_sid'),'[]'::jsonb)
                from jsonb_array_elements(s.snapshot->'local_groups'->'groups') g)))
            from roots r join latest_snapshots s using(agent_id,source_instance_id,collection_scope_id)
            where (coalesce(p_path,'')='' or lower(p_path)=lower(r.path))
              and (coalesce(p_operation,'')='' or p_operation='permissions')),
            '[]'::jsonb) else '[]'::jsonb end) into v_result;
    return v_result;
end $$;

reset role;
set local role adlog_storage_owner;
insert into public.schema_migrations(version,name) values(288,'file_audit_service_filter');
commit;
