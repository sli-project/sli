using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Storage.EventReports;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Ad;

internal static class AdAccountEvents
{
    // The daily half never overlaps individual rows. Rare changes remain exact
    // in the cold facts table after their hot partition has expired.
    // $1 = kinds, $2/$3 = half-open observation window for all callers.
    internal static string Source(IConfiguration? config, bool daily = true, string scope = "", string filter = "",
        bool hot = true, string hotFilter = "")
    {
        string boundary = Boundary(config);
        string ExactRows(string table, string retention, string extra = "") => $"""
            select h.event_id as id,h.time_created_utc,h.event_kind as event_id,h.domain_id,
                   h.actor,h.target,h.source,h.computer,h.method,h.outcome,h.fields,
                   (h.method->>'$server_id')::bigint as server_id,
                   h.method->>'$channel' as channel,h.method->>'$provider' as provider_name,
                   null::date as day,1::bigint as event_count,h.time_created_utc as first_seen_utc,
                   h.time_created_utc as last_seen_utc,''::text as summary_key
            from {table} h where h.time_created_utc{retention}{boundary}
              and h.time_created_utc >= $2 and h.time_created_utc < $3 and h.event_kind=any($1)
              {scope} {filter} {extra}
            """;
        string shortRows = (hot ? ExactRows("event_hot", ">=", hotFilter) + "\nunion all\n" : "")
            + ExactRows("event_cold_facts", "<");
        if (daily) shortRows += $"""

            union all
            select null::bigint,h.day::timestamp at time zone 'UTC',h.event_kind,h.domain_id,
                   h.actor,h.target,h.source,h.computer,h.method,h.outcome,jsonb_build_object(),
                   (h.method->>'$server_id')::bigint,h.method->>'$channel',h.method->>'$provider',
                   h.day,h.event_count,h.first_seen_utc,h.last_seen_utc,encode(h.grouping_key,'hex')
            from event_cold_daily h where h.day<({boundary} at time zone 'UTC')::date
              and h.day>=($2 at time zone 'UTC')::date and h.day<=($3 at time zone 'UTC')::date
              and h.last_seen_utc >= $2 and h.first_seen_utc < $3 and h.event_kind=any($1)
              {scope} {filter}
            """;
        // Keep the final window test on the clipped timestamp for daily rows.
        return "with short_rows as (" + shortRows + """
            ), account_events as (
            select s.id,s.id as event_db_id,s.event_id,s.domain_id,s.server_id,
                   case when s.day is null then s.time_created_utc when s.first_seen_utc<$2 then s.last_seen_utc else s.first_seen_utc end as time_created_utc,
                   s.actor,s.target,s.source,s.computer,s.method,s.outcome,s.fields,s.channel,s.provider_name,
                   s.day,case when s.day is not null and (s.first_seen_utc<$2 or s.last_seen_utc>=$3) then null else s.event_count end as event_count,
                   case when s.day is not null and s.first_seen_utc<$2 then s.last_seen_utc else s.first_seen_utc end as first_seen_utc,
                   case when s.day is not null and s.last_seen_utc>=$3 then s.first_seen_utc else s.last_seen_utc end as last_seen_utc,s.summary_key,
                   case when s.event_id=4624 then
                     case when s.actor ilike 'S-1-%' then s.actor end
                     else case when s.target ilike 'S-1-%' then s.target end end as target_user_sid,
                   case when s.event_id<>4624 and s.actor ilike 'S-1-%' then s.actor end as subject_user_sid,
                   case when s.event_id=4624 and s.actor not ilike 'S-1-%' then
                     case when strpos(s.actor,chr(92))>0 then split_part(s.actor,chr(92),2) else s.actor end end as target_user_name,
                   case when s.event_id=4624 and s.actor not ilike 'S-1-%' and strpos(s.actor,chr(92))>0 then split_part(s.actor,chr(92),1) end as target_domain_name,
                   case when s.event_id<>4624 and s.actor not ilike 'S-1-%' then
                     case when strpos(s.actor,chr(92))>0 then split_part(s.actor,chr(92),2) else s.actor end end as subject_user_name,
                   case when s.event_id<>4624 and s.actor not ilike 'S-1-%' and strpos(s.actor,chr(92))>0 then split_part(s.actor,chr(92),1) end as subject_domain_name,
                   s.method->>'LogonType' as logon_type,s.fields->>'TargetLogonId' as logon_id,
                   s.fields->>'MemberSid' as membership_member_sid,
                   jsonb_build_object('relation_member_sid',s.fields->>'MemberSid','relation_group_sid',s.target,
                     'object',s.target,'attribute',s.fields->>'AttributeLDAPDisplayName',
                     'value',s.fields->>'AttributeValue','operation',s.fields->>'OperationType') as facts_json,
                   null::text as processing_status,
                   case when s.day is null then 'short_event' else 'daily_summary' end as read_representation,
                   case s.event_id when 4624 then 'authentication.session.created'
                     when 4722 then 'directory.account.enabled' when 4725 then 'directory.account.disabled'
                     when 4728 then 'group.member.added' when 4732 then 'group.member.added' when 4756 then 'group.member.added'
                     when 4729 then 'group.member.removed' when 4733 then 'group.member.removed' when 4757 then 'group.member.removed' end as semantic_type,
                   null::uuid as normalized_event_id
            from short_rows s
            join servers recorder on recorder.id=s.server_id and recorder.domain_id=s.domain_id and recorder.role='domain_controller'
            where s.channel='Security' and s.provider_name='Microsoft-Windows-Security-Auditing'
            )
            """;
    }

    internal static string Boundary(IConfiguration? config) =>
        "timestamptz '" + EventReadService.ShortBoundary(config).ToString("O", CultureInfo.InvariantCulture) + "'";

    // Match string.Trim() for the SID and logon type fields read by .NET.
    internal const string Whitespace = "U&'\\0009\\000A\\000B\\000C\\000D\\0020\\0085\\00A0\\1680\\2000\\2001\\2002\\2003\\2004\\2005\\2006\\2007\\2008\\2009\\200A\\2028\\2029\\202F\\205F\\3000'";
    internal const string ExactSid = "btrim(h.actor," + Whitespace + ") collate \"C\"";
    internal const string LogonType = "btrim(h.method->>'LogonType'," + Whitespace + ") collate \"C\"";
    internal const string LogonFilter = "h.event_kind=4624 and h.method->>'$channel'='Security' " +
        "and h.method->>'$provider'='Microsoft-Windows-Security-Auditing' and h.actor ilike 'S-1-%'";
    private const string WorkplaceWidth = "octet_length(h.actor)+octet_length(h.source)";

    private static string WorkplaceSql(IConfiguration? config, string scope, string filter, string sidFilter) =>
        Source(config, scope: scope, filter: filter + sidFilter, hotFilter: $" and {WorkplaceWidth}>2400") + $"""
            , workplace_candidates as (
                select domain_id,target_user_sid,logon_type,source,last_seen_utc,time_created_utc,id,summary_key
                from account_events where time_created_utc>=$2 and time_created_utc<$3
                union all
                select h.domain_id,h.actor,h.ad_user_workplace_type435::text,h.source,
                       h.time_created_utc,h.time_created_utc,h.event_id,''::text
                from event_hot h join servers recorder on recorder.id=h.ad_user_logon_recorder435
                    and recorder.domain_id=h.domain_id and recorder.role='domain_controller'
                where h.ad_user_logon_recorder435 is not null and h.ad_user_workplace_type435 is not null
                    and h.actor ilike 'S-1-%' and h.source is not null and {WorkplaceWidth}<=2400
                    and h.time_created_utc>={Boundary(config)} and h.time_created_utc>=$2 and h.time_created_utc<$3
                    {scope} {sidFilter}
            )
            select domain_id,target_user_sid,logon_type,source,last_seen_utc from (
                select distinct on (domain_id,target_user_sid,source) * from workplace_candidates
                order by domain_id,target_user_sid,source,last_seen_utc desc,time_created_utc,id,summary_key
            ) latest order by time_created_utc,id,summary_key
            """;

    private const string LogonColumns = """
        id,event_db_id,event_id,domain_id,server_id,channel,provider_name,
        time_created_utc,source,computer,day,event_count,first_seen_utc,last_seen_utc,summary_key,
        target_user_sid,target_user_name,target_domain_name,logon_type,logon_id,read_representation
        """;

    internal static Task<List<JsonObject>> ReadAsync(NpgsqlConnection db,long[]? domains,int[] codes,
        AdPeriod period,CancellationToken ct,IConfiguration? config=null,long[]? servers=null,bool daily=true)
        => ReadRowsAsync(db, domains, codes, period, ct, config, servers, daily, columns: null);

    internal static Task<List<JsonObject>> ReadLogonsAsync(NpgsqlConnection db, long domain, long[] servers,
        AdPeriod period, CancellationToken ct, IConfiguration? config)
        => ReadRowsAsync(db, [domain], [4624], period, ct, config, servers, daily: true, columns: LogonColumns);

    internal static Task<List<JsonObject>> ReadWorkplaceLogonsAsync(NpgsqlConnection db, long[] domains, string[] sids,
        AdPeriod period, CancellationToken ct, IConfiguration? config)
        => ReadRowsAsync(db, domains, [4624], period, ct, config, servers: null, daily: true,
            columns: "domain_id,target_user_sid,logon_type,source,last_seen_utc", workplaceSids: sids);

    internal static Task<List<JsonObject>> ReadUserLogonsAsync(NpgsqlConnection db, long[] domains, string[] sids,
        AdPeriod period, CancellationToken ct, IConfiguration? config, bool ignoreCase)
        => ReadRowsAsync(db, domains, [4624], period, ct, config, servers: null, daily: true,
            columns: LogonColumns + ",semantic_type", userSids: sids, ignoreCase: ignoreCase);

    private static async Task<List<JsonObject>> ReadRowsAsync(NpgsqlConnection db, long[]? domains, int[] codes,
        AdPeriod period, CancellationToken ct, IConfiguration? config, long[]? servers, bool daily, string? columns,
        string[]? workplaceSids = null, string[]? userSids = null, bool ignoreCase = true)
    {
        var args = new List<object?> { codes,period.Start,period.End };
        string scope = "", filter = "", sidFilter = "", recorder = "";
        if(domains is not null){args.Add(domains);scope+=" and h.domain_id=any($"+args.Count+")";}
        if(servers is not null){args.Add(servers);recorder+=" and server_id=any($"+args.Count+")";}
        if (workplaceSids is not null)
            filter = $" and {LogonFilter} and h.source is not null and {LogonType} in ('2','10','11')";
        else if (userSids is not null) filter = " and " + LogonFilter;
        if ((workplaceSids ?? userSids) is {} sids)
        {
            // The C collation handles ASCII case. Leave Unicode SID matching to .NET.
            if (!ignoreCase || sids.All(sid => sid.All(char.IsAscii)))
            {
                args.Add(ignoreCase ? sids.Select(sid => sid.ToLowerInvariant()).ToArray() : sids);
                string match = $"lower({ExactSid})=any(${args.Count})";
                if (ignoreCase && (workplaceSids is not null || !sids.All(IsNumericSid))) match += $" or {ExactSid} ~ '[^ -~]'";
                sidFilter = ignoreCase ? $" and ({match})" : $" and {ExactSid}=any(${args.Count})"
                    + $" and lower({ExactSid})=any(array(select lower(sid collate \"C\") from unnest(${args.Count}::text[]) as value(sid)))";
            }
        }
        string matching = " from account_events where time_created_utc>=$2 and time_created_utc<$3" + recorder;
        string sql = workplaceSids is not null ? WorkplaceSql(config, scope, filter, sidFilter)
            : Source(config, daily, scope, filter + sidFilter) + " select " + (columns ?? "*")
                + matching + " order by time_created_utc,id,summary_key";
        await using var command=new NpgsqlCommand(sql,db){CommandTimeout=0};
        foreach(var arg in args)command.Parameters.Add(new(){Value=arg??DBNull.Value});
        var rows=new List<JsonObject>();await using var reader=await command.ExecuteReaderAsync(ct);
        while(await reader.ReadAsync(ct)){
            var row=new JsonObject();
            for(int i=0;i<reader.FieldCount;i++)row[reader.GetName(i)]=reader.IsDBNull(i)?null:System.Text.Json.JsonSerializer.SerializeToNode(reader.GetValue(i));
            if(columns is null)row["facts_json"]=JsonNode.Parse(row.Text("facts_json")??"{}");
            string? source=row.Text("source");
            row["ip_address"]=System.Net.IPAddress.TryParse(source,out _)?source:null;
            row["workstation_name"]=row["ip_address"] is null?source:null;
            rows.Add(row);
        }
        return rows;
    }

    private static bool IsNumericSid(string sid) => sid.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase)
        && sid.AsSpan(4).IndexOfAnyExcept("0123456789-") < 0;

    internal static string Identity(JsonObject row) => new JsonArray(row["time_created_utc"]?.DeepClone(),row["id"]?.DeepClone(),row["summary_key"]?.DeepClone()).ToJsonString();
}
