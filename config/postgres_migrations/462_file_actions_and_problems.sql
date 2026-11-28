begin;
select pg_advisory_xact_lock(hashtext('sli_file_actions_and_problems462'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=461 and name='account_check_cleanup')
       or exists(select 1 from public.schema_migrations where version>=462) then
        raise exception 'file_actions_and_problems462_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

-- Match the authenticated collector's source to the same domain registry
-- identities accepted by the File Servers report. Ambiguous domains still fail.
do $$
declare definition text;
    old_join constant text := 'left join public.servers server on server.hostname=inbox.packet#>>''{header,source}''';
    new_join constant text := 'left join public.servers server on (lower(server.hostname)=lower(inbox.packet#>>''{header,source}'') or lower(server.fqdn)=lower(inbox.packet#>>''{header,source}''))';
begin
    definition := pg_get_functiondef('public.semantic_finding_in_domains_v265(bigint,bigint[])'::regprocedure);
    if strpos(definition,old_join)=0 then
        raise exception 'file_actions_and_problems462_domain_reader_shape' using errcode='55000';
    end if;
    execute replace(definition,old_join,new_join);
end $$;

create function public.file_action_page462(
    p_roots jsonb,p_start timestamptz,p_end timestamptz,p_path text,p_nested boolean,
    p_employee text,p_operation text,p_after jsonb,p_limit integer)
returns jsonb language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare result jsonb;
begin
    if jsonb_typeof(p_roots) is distinct from 'array' or jsonb_array_length(p_roots)>1000
       or p_start is null or p_end is null or p_end<=p_start or p_end-p_start>interval '31 days'
       or p_limit is null or p_limit<1 or p_limit>200 or length(p_path)>4096 or length(p_employee)>256 then
        raise exception 'file_audit_report_parameters_invalid' using errcode='22023';
    end if;
    with roots as materialized (
        select distinct agent_id,source_instance_id,collection_scope_id
        from jsonb_to_recordset(p_roots) r(agent_id uuid,source_instance_id text,collection_scope_id text)
    ), filtered as materialized (
        select a.*,old.path as old_path
        from sli_plugin_file_audit.actions a join roots using(agent_id,source_instance_id,collection_scope_id)
        left join lateral (
            select o.normalized->>'path' as path
            from sli_plugin_file_audit.action_evidence edge
            join sli_plugin_file_audit.observations o using(evidence_key)
            where a.operation='rename' and edge.action_id=a.action_id and edge.role='handle_context'
              and o.event_id=4663
            order by o.record_id desc limit 1
        ) old on true
        where a.observed_at>=p_start and a.observed_at<p_end
          and (coalesce(p_path,'')='' or public.file_audit_path_in_root_v264(a.path,p_path) and p_nested
               or lower(a.path)=lower(p_path) or lower(old.path)=lower(p_path)
               or old.path is not null and p_nested and public.file_audit_path_in_root_v264(old.path,p_path))
          and (coalesce(p_employee,'')='' or a.subject_sid=p_employee)
          and (coalesce(p_operation,'')='' or a.operation=p_operation)
          and (p_after->>'activity' is distinct from 'changes' or a.operation in ('write','rename'))
          and (a.operation<>'access_check' or a.outcome='failure')
          and (a.operation<>'delete_right' or not exists (
              select 1 from sli_plugin_file_audit.action_evidence primary_edge
              join sli_plugin_file_audit.action_evidence context_edge using(evidence_key)
              join sli_plugin_file_audit.actions rename on rename.action_id=context_edge.action_id
              where primary_edge.action_id=a.action_id and primary_edge.role='primary'
                and context_edge.role='handle_context' and rename.operation='rename'
                and rename.agent_id=a.agent_id and rename.source_instance_id=a.source_instance_id
                and rename.collection_scope_id=a.collection_scope_id
                and rename.observed_at between a.observed_at and a.observed_at+interval '5 minutes'
          ))
    ), page as materialized (
        select * from filtered where p_after->>'at' is null
            or (observed_at,action_id)<((p_after->>'at')::timestamptz,p_after->>'id')
        order by observed_at desc,action_id desc limit p_limit+1
    ), selected as (
        select * from page order by observed_at desc,action_id desc limit p_limit
    )
    select jsonb_build_object('service_filter_version',1,'items',coalesce((select jsonb_agg(
        to_jsonb(q)||jsonb_build_object('id',q.action_id,'evidence',(
            select coalesce(jsonb_agg(jsonb_build_object(
                'reference',e.core_evidence_ref,'event_id',o.event_id,'record_id',o.record_id,
                'generation',o.generation,'role',e.role,'payload_sha256',o.payload_sha256,
                'path',o.normalized->>'path') order by e.core_evidence_ref),'[]'::jsonb)
            from sli_plugin_file_audit.action_evidence e
            left join sli_plugin_file_audit.observations o using(evidence_key)
            where e.action_id=q.action_id)) order by q.observed_at desc,q.action_id desc)
        from selected q),'[]'::jsonb),
        'filtered_count',(select count(*) from filtered),
        'has_more',(select count(*)>p_limit from page),
        'after',(select jsonb_build_object('at',observed_at,'id',action_id)
            from selected order by observed_at desc,action_id desc offset p_limit-1 limit 1)) into result;
    return result;
end $$;

create function public.file_action_problems462(p_rows jsonb)
returns table(row_id text,finding_id bigint)
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select distinct a.action_id,published.finding_id
    from jsonb_to_recordset(p_rows) selected(id text,agent_id uuid,source_instance_id text,collection_scope_id text)
    join sli_plugin_file_audit.actions a on a.action_id=selected.id and a.agent_id=selected.agent_id
        and a.source_instance_id=selected.source_instance_id and a.collection_scope_id=selected.collection_scope_id
    join sli_plugin_file_audit.rule_actions ra on ra.action_id=a.action_id
    join sli_plugin_file_audit.rule_results rr on rr.result_id=ra.result_id and rr.agent_id=a.agent_id
        and rr.source_instance_id=a.source_instance_id and rr.collection_scope_id=a.collection_scope_id
    join public.semantic_file_ransom_members member on member.result_id=ra.result_id and member.evaluation_mode='enabled'
    join public.semantic_file_ransom_episodes episode using(episode_key)
    join public.semantic_security_scenarios scenario on scenario.scenario_kind='qw.file-ransom'
        and scenario.strict_keys_json->>'episode'=episode.episode_key
        and scenario.strict_keys_json->>'entity'=episode.entity_key
    join public.semantic_finding_publications published using(scenario_id)
    where jsonb_array_length(p_rows)<=200 and member.scope_json=episode.scope_json
        and episode.scope_json->>'plugin_id'='sli.file-audit'
        and episode.scope_json->>'source_instance_id'=a.source_instance_id
        and episode.scope_json->>'collection_scope_id'=a.collection_scope_id
$$;

create function public.file_ransom_problem_facts462(p_ids bigint[],p_domains bigint[])
returns table(finding_id bigint,facts jsonb)
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select distinct on (published.finding_id) published.finding_id,
        jsonb_build_object('files',(rr.result#>>'{details,distinct_files}')::bigint,
            'minutes', greatest(1,ceil(extract(epoch from (
                (rr.result#>>'{details,window_end}')::timestamptz -
                (rr.result#>>'{details,window_start}')::timestamptz))/60)),
            'share',activity.share,'folder',activity.folder,'subject_sid',rr.result->>'subject_sid','account_at',rr.observed_at)
    from unnest(p_ids) requested(id)
    join public.semantic_finding_publications published on published.finding_id=requested.id
    join public.semantic_security_scenarios scenario on scenario.scenario_id=published.scenario_id
        and scenario.scenario_kind='qw.file-ransom'
    join public.semantic_file_ransom_episodes episode on episode.episode_key=scenario.strict_keys_json->>'episode'
        and episode.entity_key=scenario.strict_keys_json->>'entity'
    join public.semantic_file_ransom_members member using(episode_key)
    join sli_plugin_file_audit.rule_results rr on rr.result_id=member.result_id
    cross join lateral (
        select min(nullif(a.share_name,'')) as share,
            case when count(distinct lower(regexp_replace(a.path,'[^\\]+$','')))=1
                then min(regexp_replace(a.path,'[^\\]+$','')) end as folder
        from sli_plugin_file_audit.rule_actions ra join sli_plugin_file_audit.actions a using(action_id)
        where ra.result_id=rr.result_id
    ) activity
    where cardinality(p_ids)<=200 and (p_domains is null or public.semantic_finding_in_domains_v265(published.finding_id,p_domains))
    order by published.finding_id,(rr.result#>>'{details,distinct_files}')::bigint desc,rr.observed_at desc,rr.result_id
$$;

revoke all on function public.file_action_page462(jsonb,timestamptz,timestamptz,text,boolean,text,text,jsonb,integer),
    public.file_action_problems462(jsonb),public.file_ransom_problem_facts462(bigint[],bigint[]) from public;
grant execute on function public.file_action_page462(jsonb,timestamptz,timestamptz,text,boolean,text,text,jsonb,integer),
    public.file_action_problems462(jsonb),public.file_ransom_problem_facts462(bigint[],bigint[]) to adlog_user;

insert into public.schema_migrations(version,name) values(462,'file_actions_and_problems');
commit;
