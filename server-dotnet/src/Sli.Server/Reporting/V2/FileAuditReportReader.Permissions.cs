namespace Sli.Server.Reporting.V2;

public sealed partial class FileAuditReportReader
{
    // The caller supplies authorized roots. The writer retains a hot copy and a durable fact for each permission change.
    // Merge only the two candidate pages. Counts, filtering and keyset comparisons still run in one PostgreSQL snapshot.
    private const string PermissionChangesSql = """
        with roots as materialized (
            select distinct agent_id, source_instance_id, collection_scope_id, path
            from jsonb_to_recordset($1::jsonb) r(agent_id uuid, source_instance_id text, collection_scope_id text, path text, source_kind text)
            where coalesce(source_kind,'server')='server'
        ), legacy as materialized (
            select sli_plugin_file_audit.report_rows($1::jsonb,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10) as data
        ), native as materialized (
            select encode(sha256(convert_to('file-audit-native:'||f.event_id::text,'UTF8')),'hex') as id,
                f.time_created_utc as observed_at, r.agent_id, r.source_instance_id, r.collection_scope_id,
                f.actor, f.event_id, f.event_kind, f.event_record_id, f.fields->>'path' as path,
                f.method#>>'{$origin,source_generation}' as generation, encode(f.source_sha256,'hex') as payload_sha256
            from public.event_cold_facts f
            join roots r on f.method#>>'{$origin,agent_id}'=r.agent_id::text
                and f.method#>>'{$origin,source_instance_id}'=r.source_instance_id
                and f.method#>>'{$origin,collection_scope_id}'=r.collection_scope_id
            where f.time_created_utc >= $3 and f.time_created_utc < $4
                and f.event_kind=4670 and f.fields->>'operation'='permissions' and f.outcome->>'outcome'='success'
                and f.method#>>'{$origin,plugin_id}'='sli.file-audit'
                and f.method->>'operation'='permissions' and f.method->>'$channel'='Security'
                and f.method->>'$provider'='Microsoft-Windows-Security-Auditing'
                and f.source_sha256 is not null and f.event_record_id>0
                and (coalesce($8,'')='' or $8='permissions')
                and (coalesce($7,'')='' or f.actor=$7)
                and (lower((f.fields->>'path') collate pg_catalog.pg_unicode_fast)=lower(r.path collate pg_catalog.pg_unicode_fast)
                    or starts_with(lower((f.fields->>'path') collate pg_catalog.pg_unicode_fast),
                        rtrim(lower(r.path collate pg_catalog.pg_unicode_fast),E'\\')||E'\\'))
                and (coalesce($5,'')='' or lower(f.fields->>'path')=lower($5)
                    or $6 and starts_with(lower(f.fields->>'path'),rtrim(lower($5),E'\\')||E'\\'))
        ), native_page as (
            select * from native where $9->>'at' is null or
                (observed_at,id)<(($9->>'at')::timestamptz,$9->>'id')
            order by observed_at desc,id desc limit ($10+1)
        ), merged as materialized (
            select row->>'id' as id,(row->>'observed_at')::timestamptz as observed_at,row
            from legacy cross join lateral jsonb_array_elements(data->'items') l(row)
            union all
            select p.id,p.observed_at,jsonb_build_object('id',p.id,'action_id',p.id,'observed_at',p.observed_at,
                'agent_id',p.agent_id,'source_instance_id',p.source_instance_id,'collection_scope_id',p.collection_scope_id,
                'subject_sid',p.actor,'path',p.path,'operation','permissions','outcome','success','correlation_state','not_attempted',
                'evidence',jsonb_build_array(jsonb_build_object('reference','event_cold_facts:'||p.event_id::text,
                    'event_id',p.event_kind,'record_id',p.event_record_id,'generation',p.generation,'role','primary',
                    'path',p.path,'operation','permissions','payload_sha256',p.payload_sha256)))
            from native_page p
            order by observed_at desc,id desc limit ($10+1)
        ), page as materialized (
            select * from merged order by observed_at desc,id desc limit $10
        )
        select data || jsonb_build_object(
            'items',coalesce((select jsonb_agg(row order by observed_at desc,id desc) from page),'[]'::jsonb),
            'filtered_count',(data->>'filtered_count')::bigint+(select count(*) from native),
            'has_more',(data->>'has_more')::boolean or (select count(*)>$10 from merged),
            'after',(select jsonb_build_object('at',observed_at,'id',id)
                from page order by observed_at desc,id desc offset ($10-1) limit 1)) as data
        from legacy
        """;
}
