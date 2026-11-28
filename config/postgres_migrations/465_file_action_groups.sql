begin;
select pg_advisory_xact_lock(hashtext('sli_file_action_groups465'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=464 and name='file_ransom_episodes')
       or exists(select 1 from public.schema_migrations where version>=465) then
        raise exception 'file_action_groups465_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

create function public.file_action_group_page465(
    p_roots jsonb,p_tab text,p_start timestamptz,p_end timestamptz,p_path text,p_nested boolean,
    p_employee text,p_operation text,p_after jsonb,p_limit integer)
returns jsonb language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare result jsonb;
begin
    if jsonb_typeof(p_roots) is distinct from 'array' or jsonb_array_length(p_roots)>1000
       or p_tab not in ('actions','access-denials')
       or p_start is null or p_end is null or p_end<=p_start or p_end-p_start>interval '31 days'
       or p_limit is null or p_limit not between 1 and 200 or length(p_path)>4096 or length(p_employee)>256 then
        raise exception 'file_audit_report_parameters_invalid' using errcode='22023';
    end if;
    with roots as materialized (
        select distinct agent_id,source_instance_id,collection_scope_id
        from jsonb_to_recordset(p_roots) r(agent_id uuid,source_instance_id text,collection_scope_id text)
    ), observations as materialized (
        select a.*,primary_event.evidence_key,primary_event.event_id,primary_event.generation,old.path as old_path,
            date_bin(interval '1 minute',a.observed_at,timestamptz '2000-01-01 00:00:00+00') as minute,
            lower(replace(a.path,'/',chr(92)) collate pg_catalog.pg_unicode_fast) as object_key,
            lower(a.subject_sid) as account_key,
            regexp_replace(lower(replace(a.path,'/',chr(92)) collate pg_catalog.pg_unicode_fast),'[^\\]+$','') as parent_key
        from sli_plugin_file_audit.actions a join roots using(agent_id,source_instance_id,collection_scope_id)
        left join lateral (
            select edge.evidence_key,o.event_id,o.generation
            from sli_plugin_file_audit.action_evidence edge
            left join sli_plugin_file_audit.observations o using(evidence_key)
            where edge.action_id=a.action_id and edge.role='primary'
            order by edge.evidence_key limit 1
        ) primary_event on true
        left join lateral (
            select o.normalized->>'path' as path
            from sli_plugin_file_audit.action_evidence edge
            join sli_plugin_file_audit.observations o using(evidence_key)
            where a.operation='rename' and edge.action_id=a.action_id and edge.role='handle_context'
              and o.event_id=4663
            order by o.record_id desc limit 1
        ) old on true
        where a.observed_at>=p_start and a.observed_at<p_end
          and (p_tab='actions' or a.outcome='failure')
          and (coalesce(p_employee,'')='' or a.subject_sid=p_employee)
          and (a.operation<>'access_check' or a.outcome='failure')
    ), child_writes as (
        select distinct agent_id,source_instance_id,collection_scope_id,generation,minute,account_key,
            logon_id,server_process_id,parent_key
        from observations
        where operation='write' and event_id=4663 and outcome='success' and object_type<>'directory'
          and generation is not null and account_key is not null and logon_id is not null
    ), primary_writes as (
        select distinct evidence_key,collection_scope_id
        from observations where operation='write' and evidence_key is not null
    ), filtered as (
        select o.*
        from observations o
        where (coalesce(p_path,'')='' or lower(o.path)=lower(p_path) or lower(o.old_path)=lower(p_path)
            or p_nested and (public.file_audit_path_in_root_v264(o.path,p_path)
                or o.old_path is not null and public.file_audit_path_in_root_v264(o.old_path,p_path)))
          and (coalesce(p_operation,'')='' or o.operation=p_operation
               or p_operation='access_denied' and o.outcome='failure')
          and (p_after->>'activity' is distinct from 'changes' or o.operation in ('write','rename'))
          -- One 4663 can project both WriteData and DELETE. The write carries the same saved record.
          and (o.operation<>'delete_right' or p_operation='delete_right' or not exists (
              select 1 from primary_writes w where w.evidence_key=o.evidence_key
                and w.collection_scope_id=o.collection_scope_id))
          and (o.operation<>'delete_right' or not exists (
              select 1 from sli_plugin_file_audit.action_evidence edge
              join sli_plugin_file_audit.actions rename on rename.action_id=edge.action_id
              where edge.evidence_key=o.evidence_key and edge.role='handle_context' and rename.operation='rename'
                and rename.agent_id=o.agent_id and rename.source_instance_id=o.source_instance_id
                and rename.collection_scope_id=o.collection_scope_id
                and rename.observed_at between o.observed_at and o.observed_at+interval '5 minutes'))
          -- Keep a standalone directory write. Fold a parent only when a direct child write
          -- corroborates it in the same collector generation, logon, process and minute.
          and (o.operation<>'write' or o.object_type='file' or o.event_id is distinct from 4663
               or (coalesce(o.access_mask,0)&2)=0
               or o.outcome<>'success' or not exists (
              select 1 from child_writes w where w.agent_id=o.agent_id and w.source_instance_id=o.source_instance_id
                and w.collection_scope_id=o.collection_scope_id and w.generation=o.generation and w.minute=o.minute
                and w.account_key=o.account_key and w.logon_id=o.logon_id
                and w.server_process_id is not distinct from o.server_process_id
                and w.parent_key=rtrim(o.object_key,chr(92))||chr(92)))
    ), groups as materialized (
        select (array_agg(action_id order by observed_at desc,action_id desc))[1] as id,
            array_agg(action_id) as members,min(observed_at) as first_seen,max(observed_at) as last_seen,
            count(*) as weight
        from filtered
        group by agent_id,source_instance_id,collection_scope_id,generation,minute,account_key,
            case when generation is null or account_key is null or object_key is null then action_id end,
            operation,object_key,lower(old_path),event_id,outcome,denial_layer,
            case when outcome='failure' then client_ip end,case when outcome='failure' then access_mask end
    ), page as materialized (
        select * from groups where p_after->>'at' is null
            or (last_seen,id)<((p_after->>'at')::timestamptz,p_after->>'id')
        order by last_seen desc,id desc limit p_limit+1
    ), selected as (
        select * from page order by last_seen desc,id desc limit p_limit
    )
    select jsonb_build_object('service_filter_version',1,
        'items',coalesce((select jsonb_agg(to_jsonb(a)||jsonb_build_object(
            'id',g.id,'old_path',o.old_path,'event_code',o.event_id,'journal',case when o.event_id is not null then 'Security' end,
            'record_unit','action_group','count',g.weight,'first_seen_utc',g.first_seen,'last_seen_utc',g.last_seen,
            'aggregate',jsonb_build_object('unit','action_group','count',g.weight,
                'first_seen_utc',g.first_seen,'last_seen_utc',g.last_seen,'boundary','inside'),
            'member_actions',to_jsonb(g.members),
            'evidence',(select coalesce(jsonb_agg(jsonb_build_object(
                'reference',e.core_evidence_ref,'event_id',x.event_id,'record_id',x.record_id,'generation',x.generation,
                'role',e.role,'payload_sha256',x.payload_sha256,'path',x.normalized->>'path')
                order by (e.role='primary') desc,e.core_evidence_ref),'[]'::jsonb)
                from sli_plugin_file_audit.action_evidence e
                left join sli_plugin_file_audit.observations x using(evidence_key)
                where e.action_id=g.id)) order by g.last_seen desc,g.id desc)
            from selected g join observations o on o.action_id=g.id
            join sli_plugin_file_audit.actions a on a.action_id=g.id),'[]'::jsonb),
        'filtered_count',(select count(*) from groups),
        'has_more',(select count(*)>p_limit from page),
        'after',(select jsonb_build_object('at',last_seen,'id',id)
            from selected order by last_seen desc,id desc offset p_limit-1 limit 1))
    into result;
    return result;
end $$;

-- Bind a report row to a published scenario through its actual scoped rule result.
create function public.file_mass_problem_links465(p_rows jsonb)
returns table(row_id text,finding_id bigint)
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select distinct rr.result_id,published.finding_id
    from jsonb_to_recordset(p_rows) selected(id text,agent_id uuid,source_instance_id text,collection_scope_id text)
    join sli_plugin_file_audit.rule_results rr on rr.result_id=selected.id and rr.agent_id=selected.agent_id
        and rr.source_instance_id=selected.source_instance_id and rr.collection_scope_id=selected.collection_scope_id
    join public.semantic_file_ransom_members member on member.result_id=rr.result_id and member.evaluation_mode='enabled'
    join public.semantic_file_ransom_episodes episode using(episode_key)
    join public.semantic_security_scenarios scenario on scenario.scenario_kind='qw.file-ransom'
        and scenario.strict_keys_json->>'episode'=episode.episode_key
        and scenario.strict_keys_json->>'entity'=episode.entity_key
    join public.semantic_finding_publications published using(scenario_id)
    where jsonb_array_length(p_rows)<=200 and member.scope_json=episode.scope_json
        and episode.scope_json->>'plugin_id'='sli.file-audit'
        and episode.scope_json->>'source_instance_id'=rr.source_instance_id
        and episode.scope_json->>'collection_scope_id'=rr.collection_scope_id
$$;

revoke all on function public.file_action_group_page465(jsonb,text,timestamptz,timestamptz,text,boolean,text,text,jsonb,integer),
    public.file_mass_problem_links465(jsonb) from public;
grant execute on function public.file_action_group_page465(jsonb,text,timestamptz,timestamptz,text,boolean,text,text,jsonb,integer),
    public.file_mass_problem_links465(jsonb) to adlog_user;

insert into public.schema_migrations(version,name) values(465,'file_action_groups');
commit;
