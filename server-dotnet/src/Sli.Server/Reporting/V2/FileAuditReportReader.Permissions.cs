namespace Sli.Server.Reporting.V2;

public sealed partial class FileAuditReportReader
{
    // One retained 4670 fact is one saved group. Both views use the same
    // interval-overlap selection; a group is never expanded into guessed events.
    private const string NativePermissionCandidates = """
        with roots as materialized (
            select distinct agent_id, source_instance_id, collection_scope_id, path
            from jsonb_to_recordset($1::jsonb) r(agent_id uuid, source_instance_id text, collection_scope_id text, path text, source_kind text)
            where coalesce(source_kind,'server')='server'
        ), native_facts as materialized (
            select encode(sha256(convert_to('file-audit-native:'||f.event_id::text,'UTF8')),'hex') as id,
                f.time_created_utc as observed_at, r.agent_id, r.source_instance_id, r.collection_scope_id,
                f.actor, f.event_id, f.event_kind, f.event_record_id, f.fields->>'path' as path,
                f.fields->>'operation' as operation, f.source as client_ip, f.outcome->>'outcome' as outcome,
                f.domain_id, f.fields->>'old_path' as old_path,
                f.method#>>'{$origin,source_generation}' as generation, encode(f.source_sha256,'hex') as payload_sha256,
                coalesce((f.fields#>>'{aggregate,count}')::bigint,1) as weight,
                coalesce((f.fields#>>'{aggregate,first_seen_utc}')::timestamptz,f.time_created_utc) as first_seen,
                coalesce((f.fields#>>'{aggregate,last_seen_utc}')::timestamptz,f.time_created_utc) as last_seen
            from public.event_cold_facts f
            join roots r on f.method#>>'{$origin,agent_id}'=r.agent_id::text
                and f.method#>>'{$origin,source_instance_id}'=r.source_instance_id
                and f.method#>>'{$origin,collection_scope_id}'=r.collection_scope_id
            where f.time_created_utc < $4
                -- The admitted source contract confines every group to one UTC minute.
                and f.time_created_utc >= $3-interval '1 minute'
                and f.fields->>'operation' in ('permissions','access_denied','read','write','delete','rename')
                and ($2='actions' or $2 in ('overview','permission-changes') and f.event_kind=4670
                    and f.fields->>'operation'='permissions' and f.outcome->>'outcome'='success'
                    or $2='access-denials' and f.outcome->>'outcome'='failure')
                and f.method#>>'{$origin,plugin_id}'='sli.file-audit'
                and f.method->>'operation'=f.fields->>'operation' and f.method->>'$channel'='Security'
                and f.method->>'$provider'='Microsoft-Windows-Security-Auditing'
                and f.source_sha256 is not null and f.event_record_id>0
                and (coalesce($8,'')='' or $8=f.fields->>'operation')
                and ($9->>'activity' is distinct from 'changes' or f.fields->>'operation' in ('write','rename'))
                and coalesce($9->>'record_unit','')<>'normalized_action'
                and (coalesce($7,'')='' or f.actor=$7)
                and (lower((f.fields->>'path') collate pg_catalog.pg_unicode_fast)=lower(r.path collate pg_catalog.pg_unicode_fast)
                    or starts_with(lower((f.fields->>'path') collate pg_catalog.pg_unicode_fast),
                        rtrim(lower(r.path collate pg_catalog.pg_unicode_fast),E'\\')||E'\\'))
                and (coalesce($5,'')='' or lower(f.fields->>'path')=lower($5)
                    or $6 and starts_with(lower(f.fields->>'path'),rtrim(lower($5),E'\\')||E'\\'))
        ), native as materialized (
            select *, first_seen >= $3 and last_seen < $4 as inside_window,
                case when first_seen >= $3 and last_seen < $4 then weight
                     else (case when first_seen >= $3 and first_seen < $4 then 1 else 0 end)
                        +(case when last_seen >= $3 and last_seen < $4 and last_seen<>first_seen then 1 else 0 end) end as count_min,
                weight-(case when first_seen < $3 then 1 else 0 end)
                      -(case when last_seen >= $4 and last_seen<>first_seen then 1 else 0 end) as count_max
            from native_facts where first_seen < $4 and last_seen >= $3
        )
        """;

    // Only durable facts are queried, never their duplicate hot copies.
    private const string PermissionChangesSql = NativePermissionCandidates + """
        , legacy as materialized (
            select case when $9->>'record_unit'='saved_event_group' then
                jsonb_build_object('service_filter_version',1,'items','[]'::jsonb,'filtered_count',0,'has_more',false,'after',null)
                else sli_plugin_file_audit.report_rows($1::jsonb,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10) end as data
        ), native_page as (
            select * from native where $9->>'at' is null or
                (observed_at,id)<(($9->>'at')::timestamptz,$9->>'id')
            order by observed_at desc,id desc limit ($10+1)
        ), merged as materialized (
            select row->>'id' as id,(row->>'observed_at')::timestamptz as observed_at,
                row||jsonb_build_object('record_unit','normalized_action') as row
            from legacy cross join lateral jsonb_array_elements(data->'items') l(row)
            union all
            select p.id,p.observed_at,jsonb_build_object('id',p.id,'action_id',p.id,'observed_at',p.observed_at,
                'agent_id',p.agent_id,'source_instance_id',p.source_instance_id,'collection_scope_id',p.collection_scope_id,
                'subject_sid',p.actor,'path',p.path,'old_path',p.old_path,'operation',p.operation,'outcome',p.outcome,
                'client_ip',p.client_ip,'domain_id',p.domain_id,'correlation_state','not_attempted',
                'record_unit','saved_event_group','count',p.weight,'first_seen_utc',p.first_seen,'last_seen_utc',p.last_seen,
                'aggregate',jsonb_build_object('unit','saved_event_group','count',p.weight,
                    'first_seen_utc',p.first_seen,'last_seen_utc',p.last_seen,
                    'boundary',case when p.inside_window then 'inside' else 'overlap' end,
                    'count_min',p.count_min,'count_max',p.count_max),
                'evidence',jsonb_build_array(jsonb_build_object('reference','event_cold_facts:'||p.event_id::text,
                    'event_id',p.event_kind,'record_id',p.event_record_id,'generation',p.generation,'role','primary',
                    'path',p.path,'operation',p.operation,'payload_sha256',p.payload_sha256)))
            from native_page p
            order by observed_at desc,id desc limit ($10+1)
        ), page as materialized (
            select * from merged order by observed_at desc,id desc limit $10
        )
        select data || jsonb_build_object(
            'items',coalesce((select jsonb_agg(row order by observed_at desc,id desc) from page),'[]'::jsonb),
            'filtered_count',(data->>'filtered_count')::bigint+(select count(*) from native),
            'native_group_count',(select count(*) from native),
            'native_event_count',case when not exists(select 1 from native where not inside_window) then (select coalesce(sum(weight),0) from native) end,
            'has_more',(data->>'has_more')::boolean or (select count(*)>$10 from merged),
            'after',(select jsonb_build_object('at',observed_at,'id',id)
                from page order by observed_at desc,id desc offset ($10-1) limit 1)) as data
        from legacy
        """;

    private const string PermissionOverviewSql = NativePermissionCandidates + """
        , legacy as materialized (
            -- Root rows have no actor or operation. Apply those filters only
            -- to native observations, never to the inventory root itself.
            select sli_plugin_file_audit.report_rows($1::jsonb,$2,$3,$4,$5,$6,null,null,$9::jsonb,$10) as data
        ), totals as (
            select agent_id,source_instance_id,collection_scope_id,count(*) as groups,
                count(*) filter(where not inside_window) as boundary_groups,
                sum(weight) as weight,sum(count_min) as count_min,sum(count_max) as count_max,
                min(first_seen) as first_seen,max(last_seen) as last_seen
            from native group by agent_id,source_instance_id,collection_scope_id
        )
        select data||jsonb_build_object('items',coalesce((
            select jsonb_agg(row||jsonb_build_object(
                'permission_changes',case when coalesce(t.boundary_groups,0)=0 then coalesce(t.weight,0) end,
                'permission_change_groups',coalesce(t.groups,0),
                'permission_change_count_min',coalesce(t.count_min,0),
                'permission_change_count_max',coalesce(t.count_max,0),
                'permission_change_boundary_groups',coalesce(t.boundary_groups,0),
                'first_permission_change',t.first_seen,'last_permission_change',t.last_seen,
                'permission_change_unit','saved_4670_events') order by n)
            from jsonb_array_elements(data->'items') with ordinality l(row,n)
            left join totals t on t.agent_id::text=row->>'agent_id'
                and t.source_instance_id=row->>'source_instance_id' and t.collection_scope_id=row->>'collection_scope_id'
        ),'[]'::jsonb)) as data from legacy
        """;
}
