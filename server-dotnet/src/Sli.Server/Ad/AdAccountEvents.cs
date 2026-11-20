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
    internal static string Source(IConfiguration? config, bool daily = true)
    {
        string boundary = "timestamptz '" + EventReadService.ShortBoundary(config).ToString("O",CultureInfo.InvariantCulture) + "'";
        return "with short_rows as (" + EventReadService.ShortSource(boundary,daily) + $"""

            union all
            select h.event_id,h.time_created_utc,h.event_kind,h.domain_id,
                   h.actor,h.target,h.source,h.computer,h.method,h.outcome,h.fields,
                   (h.method->>'$server_id')::bigint,h.method->>'$channel',h.method->>'$provider',
                   null::date,1::bigint,h.time_created_utc,h.time_created_utc,''::text
            from event_cold_facts h where h.time_created_utc<{boundary}
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

    private static async Task<List<JsonObject>> ReadRowsAsync(NpgsqlConnection db, long[]? domains, int[] codes,
        AdPeriod period, CancellationToken ct, IConfiguration? config, long[]? servers, bool daily, string? columns)
    {
        var args = new List<object?> { codes,period.Start,period.End };
        string scope="";
        if(domains is not null){args.Add(domains);scope+=" and domain_id=any($"+args.Count+")";}
        if(servers is not null){args.Add(servers);scope+=" and server_id=any($"+args.Count+")";}
        string sql=Source(config,daily)+" select "+(columns??"*")+" from account_events where event_id=any($1) and time_created_utc>=$2 and time_created_utc<$3"+scope+" order by time_created_utc,id,summary_key";
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

    internal static string Identity(JsonObject row) => new JsonArray(row["time_created_utc"]?.DeepClone(),row["id"]?.DeepClone(),row["summary_key"]?.DeepClone()).ToJsonString();
}
