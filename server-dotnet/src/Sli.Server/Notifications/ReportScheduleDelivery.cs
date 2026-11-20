using System.Globalization;
using System.Text.Json;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Infrastructure;
namespace Sli.Server.Notifications;
public static class ReportScheduleDelivery
{
    public static async Task<JsonElement?> LoadAsync(NpgsqlConnection db,NpgsqlTransaction tx,NotificationJob job,CancellationToken ct)
    {
        // Schedule/job fence must precede the ordinary subscription locks.
        await using(var bounds=new NpgsqlCommand("select set_config('statement_timeout','2000ms',true),set_config('lock_timeout','500ms',true)",db,tx))await bounds.ExecuteNonQueryAsync(ct);
        await using var command=new NpgsqlCommand("select public.report_schedule_delivery(@id,@lease)",db,tx);command.Parameters.AddWithValue("id",job.Id);command.Parameters.AddWithValue("lease",job.Lease);
        object? value=await command.ExecuteScalarAsync(ct);if(value is not string raw)return null;
        using var json=JsonDocument.Parse(raw);return json.RootElement.ValueKind==JsonValueKind.Null?null:json.RootElement.Clone();
    }
    public static async Task<NotificationJob> AuthorizeAsync(IPostgresConnectionFactory database,NotificationJob job,JsonElement payload,CancellationToken ct)
    {
        using var budget=CancellationTokenSource.CreateLinkedTokenSource(ct);budget.CancelAfter(TimeSpan.FromSeconds(5));
        return await AuthorizeAsync(job,payload,id=>ReportScheduleAuthority.LoadAsync(database,id,budget.Token));
    }
    public static async Task<NotificationJob> AuthorizeAsync(NotificationJob job,JsonElement payload,Func<long,Task<AccessDecision?>> load)
    {
        var subscription=payload.GetProperty("subscription");var run=payload.GetProperty("run");long owner=payload.GetProperty("owner_user_id").GetInt64();
        if(run.GetProperty("id").GetGuid()!=job.ObjectId || subscription.GetProperty("id").GetGuid()!=job.Subscription || subscription.GetProperty("revision").GetInt64()!=job.Revision || subscription.GetProperty("recipient_user_id").GetInt64()!=job.Recipient || subscription.GetProperty("channel").GetString()!=job.Channel || subscription.GetProperty("owner_user_id").GetInt64()!=owner || !subscription.GetProperty("enabled").GetBoolean())throw new UnauthorizedAccessException();
        string key=run.GetProperty("report_key").GetString()!;bool count=run.GetProperty("item_count").ValueKind!=JsonValueKind.Null;
        var roots=payload.GetProperty("root_scope");if(roots.ValueKind!=JsonValueKind.Array || roots.GetArrayLength()>1000)throw new UnauthorizedAccessException();
        foreach(long user in new[]{owner,job.Recipient}.Distinct()) {
            var access=await load(user);if(access is null || !ReportScheduleAccess.Report(access,key))throw new UnauthorizedAccessException();
            if(!count)continue;
            if(!ReportScheduleAccess.Report(access,key,"export"))throw new UnauthorizedAccessException();
            if(key=="security.problems" && user==owner && payload.GetProperty("selection").Get("variant").GetString()=="cohorts" && !ResourceAccessDecisions.ReportAction(access,"security.queue","view",null,new HashSet<string>{"security","identity_basic"}).Allowed)throw new UnauthorizedAccessException();
            if(key.StartsWith("file-audit.",StringComparison.Ordinal))foreach(var root in roots.EnumerateArray()) {
                if(root.ValueKind!=JsonValueKind.Object || !new HashSet<string>{"agent_id","source_instance_id","collection_scope_id"}.SetEquals(root.EnumerateObject().Select(p=>p.Name)) || !ReportScheduleAccess.FileRoot(access,root,"view") || !ReportScheduleAccess.FileRoot(access,root,"export"))throw new UnauthorizedAccessException();
            }
        }
        return job with {ReportRun=run.Clone(),ReportChannelRevision=payload.GetProperty("channel_revision").GetInt64()};
    }
    static string Stamp(JsonElement run,string key)
    {
        var time=run.GetProperty(key).GetDateTimeOffset();string value=time.ToString("yyyy-MM-dd'T'HH:mm:ss",CultureInfo.InvariantCulture);
        if(time.Ticks%TimeSpan.TicksPerSecond!=0)value+="."+time.ToString("ffffff",CultureInfo.InvariantCulture);return value+time.ToString("zzz",CultureInfo.InvariantCulture);
    }
    public static string Title(JsonElement run)=>run.GetProperty("report_key").GetString() switch {
        "security.problems"=>run.GetProperty("language").GetString()=="ru"?"Проблемы безопасности":"Security problems",
        "file-audit.mass-operations"=>run.GetProperty("language").GetString()=="ru"?"Массовые файловые операции":"Mass file operations",_=>throw new FormatException()};
    public static string Digest(NotificationJob job,string baseUrl)
    {
        var run=job.ReportRun??throw new FormatException();string key=run.GetProperty("report_key").GetString()!;
        if(!ReportScheduleInput.Choices.TryGetValue(key,out var choices))throw new FormatException();
        var parameters=new List<KeyValuePair<string,string>>();foreach(var filter in run.GetProperty("filters").EnumerateObject())if(choices.ContainsKey(filter.Name))parameters.Add(new(filter.Name,filter.Value.GetString()!));
        string start=Stamp(run,"period_from"),end=Stamp(run,"period_to");parameters.Add(new("tz",run.GetProperty("timezone").GetString()!));
        if(key=="security.problems"){parameters.Add(new("time_from",start));parameters.Add(new("time_to",end));}
        else {parameters.Add(new("period","custom"));parameters.Add(new("from",start));parameters.Add(new("to",end));}
        string link=baseUrl.TrimEnd('/')+"/report/"+key+"?"+string.Join("&",parameters.Select(p=>Uri.EscapeDataString(p.Key)+"="+Uri.EscapeDataString(p.Value).Replace("%20","+")));
        string[] labels=run.GetProperty("language").GetString()=="ru"?["Период [от, до)","Качество","Количество","Сформировано","Усечение","Задержка","Выпуск"]:["Period [from, to)","Quality","Count","Generated","Truncated","Delayed","Run"];
        string[] values=[$"[{start}, {end})",run.GetProperty("quality").GetString()!,run.GetProperty("item_count").ValueKind==JsonValueKind.Null?"unavailable":run.GetProperty("item_count").GetInt64().ToString(CultureInfo.InvariantCulture),Stamp(run,"generated_at"),run.GetProperty("truncated").GetBoolean()?"true":"false",run.GetProperty("delayed").GetBoolean()?"true":"false",run.GetProperty("id").GetString()!];
        return Title(run)+"\n"+string.Join("\n",labels.Zip(values,(label,value)=>label+": "+value))+$"\nJob: {job.Id}\n{link}\n";
    }
}
