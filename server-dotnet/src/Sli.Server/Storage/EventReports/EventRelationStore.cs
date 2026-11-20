using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Entities;

namespace Sli.Server.Storage.EventReports;

internal sealed class EventRelationStore(Func<string,IReadOnlyDictionary<string,object>,CancellationToken,Task<List<JsonObject>>> query,IConfiguration? configuration=null,DateTimeOffset? boundary=null)
{
    static string Source => "with short_events as ("+EntityShortSql.Source("@boundary",daily:false)+"), relation_events as ("+"""
        select e.*,coalesce(e.fields->>'TargetLogonId',e.fields->>'SubjectLogonId',e.method->>'TargetLogonId',e.method->>'SubjectLogonId') as logon_id,
            e.fields->>'TaskName' as task_name
        from short_events e join servers s on s.id=e.server_id and s.domain_id=e.domain_id
        )
        """;
    internal async Task<IReadOnlyList<RelationCandidate>> QueryAsync(long anchor,int count,(decimal Delta,long Id)? after,CancellationToken ct)
    {
        var rows=await query(Source+"select e.server_id,e.time_created_utc,e.logon_id,e.task_name from relation_events e where e.id=@id limit 1",
            new Dictionary<string,object> { ["id"]=anchor,["boundary"]=boundary??EventReadService.ShortBoundary(configuration) },ct);
        if(rows.Count==0) return [];
        var row=rows[0];
        long server=EventReadService.Long(row,"server_id");
        var time=EventReadService.Stamp(row["time_created_utc"]);
        string logon=row["logon_id"]?.ToString().Trim()??"",task=row["task_name"]?.ToString().Trim()??"";
        var result=new List<RelationCandidate>();
        if(logon.Length>0 && !logon.Equals("-",StringComparison.OrdinalIgnoreCase) && !logon.Equals("0x0",StringComparison.OrdinalIgnoreCase))
            result.AddRange(await ReadRule(anchor,server,time,logon,count,after,true,ct));
        if(task.Length>0) result.AddRange(await ReadRule(anchor,server,time,task,count,after,false,ct));
        return result;
    }
    async Task<List<RelationCandidate>> ReadRule(long anchor,long server,DateTimeOffset time,string key,int count,(decimal Delta,long Id)? after,bool logon,CancellationToken ct)
    {
        using var command=CreateRuleCommand(null,null,anchor,server,time.UtcDateTime,key,count,after,logon,boundary,configuration);
        var parameters=command.Parameters.Cast<NpgsqlParameter>().ToDictionary(p=>p.ParameterName,p=>p.Value!);
        var rows=await query(command.CommandText,parameters,ct);
        var result=new List<RelationCandidate>();
        foreach(var row in rows)
        {
            var timestamp=EventReadService.Stamp(row["time_created_utc"]);
            string format=timestamp.Ticks%TimeSpan.TicksPerSecond==0 ? "yyyy-MM-dd'T'HH:mm:sszzz" : "yyyy-MM-dd'T'HH:mm:ss.ffffffzzz";
            result.Add(new(EventReadService.Long(row,"id"),checked((int)EventReadService.Long(row,"event_id")),timestamp.ToString(format,CultureInfo.InvariantCulture),
                logon ? "auth_session" : "scheduled_task",row["entity"]?.ToString()??"",logon ? "same_logon_id_same_server" : "same_task_same_server_time_window",
                decimal.Parse(row["delta"]!.ToString(),CultureInfo.InvariantCulture)));
        }
        return result;
    }
    internal static NpgsqlCommand CreateRuleCommand(NpgsqlConnection? db,NpgsqlTransaction? tx,long anchor,long server,DateTime time,string key,int count,(decimal Delta,long Id)? after,bool logon,DateTimeOffset? boundary=null,IConfiguration? configuration=null)
    {
        string field=logon ? "e.logon_id" : "e.task_name";
        string interval=logon ? "4 hours" : "1 hour";
        string cursor=after is null ? "" : "and (abs(extract(epoch from (e.time_created_utc - @base))),-e.id) > (@delta,@negid)";
        string sql=Source+$"""
            select e.id,e.event_id,e.time_created_utc,{field} as entity,abs(extract(epoch from (e.time_created_utc - @base))) as delta
            from relation_events e where {field}=@key and e.server_id=@server and e.id<>@anchor
              and e.time_created_utc between @base - interval '{interval}' and @base + interval '{interval}'
              {cursor} order by delta asc,e.id desc limit @limit
            """;
        var command=new NpgsqlCommand(sql,db,tx) { CommandTimeout=0 };
        command.Parameters.AddWithValue("boundary",boundary??EventReadService.ShortBoundary(configuration));
        command.Parameters.AddWithValue("base",NpgsqlDbType.TimestampTz,time); command.Parameters.AddWithValue("key",key);
        command.Parameters.AddWithValue("server",server); command.Parameters.AddWithValue("anchor",anchor); command.Parameters.AddWithValue("limit",count);
        if(after is {} position) { command.Parameters.AddWithValue("delta",NpgsqlDbType.Numeric,position.Delta); command.Parameters.AddWithValue("negid",-position.Id); }
        return command;
    }
}
