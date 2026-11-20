using System.Text.RegularExpressions;
using Sli.Server.Storage.EventReports;

namespace Sli.Server.Semantic;

internal sealed partial class SemanticHistorySession
{
    // Keep the existing PostgreSQL filters and resource guards. Only their
    // event inputs change; daily groups never acquire an individual event ID.
    internal static (string Sql,object?[] Values) RewriteEvents(string sql,object?[] values,IConfiguration? config)
    {
        string Pattern(string table) => @"(?<![\w.])(?:public\.)?"+table+@"\b";
        if (sql.Contains("short_semantic_events as not materialized",StringComparison.Ordinal) ||
            !Regex.IsMatch(sql,Pattern("semantic_event_rows")) && !Regex.IsMatch(sql,Pattern("semantic_event_fields"))) return (sql,values);
        var args=values.ToList(); args.Add(EventReadService.ShortBoundary(config)); string boundary="$"+args.Count;
        string ctes="""
            short_semantic_events as not materialized (
                select h.event_id,h.time_created_utc,h.event_kind,h.domain_id,h.actor,h.target,h.source,h.computer,
                    h.method,h.outcome,h.fields,h.source_sha256,h.event_record_id
                from public.event_hot h where h.time_created_utc>=__boundary__
                union all
                select f.event_id,f.time_created_utc,f.event_kind,f.domain_id,f.actor,f.target,f.source,f.computer,
                    f.method,f.outcome,f.fields,f.source_sha256,f.event_record_id
                from public.event_cold_facts f where not exists(select 1 from public.event_hot h
                    where h.event_id=f.event_id and h.time_created_utc>=__boundary__)
                union all
                select distinct on(c.event_id) c.event_id,c.time_created_utc,c.event_kind,c.domain_id,c.actor,c.target,c.source,c.computer,
                    c.method,c.outcome,c.fields,c.source_sha256,c.event_record_id
                from public.finding_event_copies337 c where not exists(select 1 from public.event_hot h
                    where h.event_id=c.event_id and h.time_created_utc>=__boundary__)
                  and not exists(select 1 from public.event_cold_facts f where f.event_id=c.event_id)
            ),
            short_semantic_data as not materialized (
                select e.*,coalesce(e.method->'$principals','{}'::jsonb)||e.method||e.outcome||e.fields as data
                from short_semantic_events e
            ),
            semantic_event_rows as not materialized (
                select e.event_id as id,e.event_kind as event_id,e.time_created_utc,server.id as server_id,e.domain_id,
                    channel.id as channel_id,provider.id as provider_id,computer.id as computer_id,keywords.id as keywords_id,e.event_record_id,
                    (e.method#>>'{$origin,log_source_id}')::bigint as log_source_id,e.source_sha256 as normalized_hash,
                    e.data->>'SubjectUserSid' as subject_user_sid,e.data->>'SubjectUserName' as subject_user_name,
                    coalesce(e.data->>'TargetSid',e.data->>'TargetUserSid') as target_user_sid,e.data->>'TargetUserName' as target_user_name,
                    subject_domain.id as subject_domain_id,target_domain.id as target_domain_id,
                    coalesce(e.data->>'IpAddress',e.data->>'ClientAddress',e.data->>'SourceNetworkAddress') as ip_address,
                    coalesce(e.data->>'WorkstationName',e.data->>'Workstation') as workstation_name,
                    coalesce(e.data->>'TargetLogonId',e.data->>'SubjectLogonId') as logon_id,
                    null::bytea as source_core_sha256,null::timestamptz as migrated_at,null::timestamptz as normalized_at,
                    null::text as correlation_id,null::text as noise_class,null::text as noise_catalog_version,
                    null::bigint as raw_log_file_id,null::bigint as site_id,null::smallint as version,null::smallint as level,
                    null::integer as task,null::integer as opcode,null::smallint as noise_catalog_revision_id
                from short_semantic_data e join public.servers server on server.id=(e.method->>'$server_id')::bigint and server.domain_id=e.domain_id
                join public.storage_v2_channel channel on channel.value=e.method->>'$channel'
                left join public.storage_v2_provider provider on provider.value=e.method->>'$provider'
                left join public.storage_v2_computer computer on computer.value=coalesce(e.method->>'$machine_name',e.computer)
                left join public.storage_v2_keywords keywords on keywords.value=e.outcome->>'keywords'
                left join public.storage_v2_domain_name subject_domain on subject_domain.value=e.data->>'SubjectDomainName'
                left join public.storage_v2_domain_name target_domain on target_domain.value=e.data->>'TargetDomainName'
            ),
            semantic_event_fields as not materialized (
                select e.event_id,coalesce(e.data->>'TargetSid',e.data->>'TargetUserSid') as account_target_sid,
                    e.data->>'TargetUserName' as account_target_name,e.data->>'OldTargetUserName' as account_name_before,
                    e.data->>'NewTargetUserName' as account_name_after,e.data->>'MemberSid' as membership_member_sid,
                    e.data->>'MemberName' as membership_member_name,coalesce(e.data->>'ResultCode',e.data->>'Status',e.data->>'SubStatus') as result_code,
                    e.data->>'LogonType' as logon_type,coalesce(e.data->>'ProcessName',e.data->>'NewProcessName') as process_name,
                    coalesce(e.data->>'ProcessId',e.data->>'NewProcessId') as process_id,e.data->>'CommandLine' as process_command_line,
                    e.data->>'ServiceName' as service_name,e.data->>'ServiceFileName' as service_file,
                    e.data->>'TaskName' as task_name,coalesce(e.data->>'ObjectName',e.data->>'ObjectDN') as object_name,
                    e.data->>'ServiceAccount' as service_account,e.data->>'ServiceStartType' as service_start_type,
                    e.data->>'task_command' as task_action,e.data->>'task_user' as run_as,e.data->>'TaskAuthor' as task_author,
                    e.data->>'UserSid' as process_user_sid,e.data->>'UserName' as process_user_name,e.data->>'UserDomain' as process_user_domain,
                    e.data->>'ParentProcessId' as process_parent_id,e.data->>'SubjectLogonId' as process_logon_id,
                    e.data->>'TargetServerName' as target_server_name,e.data->>'ShareName' as share_name,
                    null::text as task_content,null::text as task_change,null::text as message_sample,
                    null::text as powershell_user_name,null::text as powershell_command_name,
                    null::text as powershell_script_block_text,null::text as powershell_process_id,null::text as native_process_id,
                    null::bytea as source_facts_sha256,null::timestamptz as migrated_at
                from short_semantic_data e
            )
            """.Replace("__boundary__",boundary,StringComparison.Ordinal);
        var with=Regex.Match(sql,@"^\s*with\s+",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant);
        return (with.Success ? sql.Insert(with.Length,ctes+",") : "with "+ctes+" "+sql,args.ToArray());
    }
}
