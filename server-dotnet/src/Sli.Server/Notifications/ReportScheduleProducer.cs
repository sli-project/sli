using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Access;
using Sli.Server.Agents.SnapshotPublication;
namespace Sli.Server.Notifications;

public static class ReportScheduleProjection
{
    public static JsonObject Select(string key,long ownerId,IReadOnlyDictionary<long,AccessDecision> actors,IEnumerable<long> recipients,JsonElement candidate,AccessDecision? dependency=null)
    {
        if(candidate.GetProperty("report_key").GetString()!=key || !ReportScheduleInput.Choices.ContainsKey(key) || candidate.GetRawText().Length>262144)throw new FormatException();
        var selection=new JsonObject{["variant"]=null,["root_indexes"]=new JsonArray(),["qw_root_indexes"]=new JsonArray(),["include_count"]=false,["owner_state"]="denied"};
        if(!actors.TryGetValue(ownerId,out var owner) || !ReportScheduleAccess.Report(owner,key))return selection;
        selection["owner_state"]="readable";
        string? quality=candidate.Get("quality").ValueKind==JsonValueKind.String?candidate.Get("quality").GetString():null;
        if(quality is "error" or "denied" or "processing" or "not_collected")return selection;
        var roots=candidate.Get("roots").Items().ToArray();if(roots.Length>1000)throw new FormatException();
        var selected=new List<int>();var qw=new List<int>();
        if(key=="security.problems") {
            string variant=ResourceAccessDecisions.ReportAction(owner,"security.queue","view",null,new HashSet<string>{"security","identity_basic"}).Allowed?"cohorts":"individual";
            var counts=candidate.GetProperty("counts");
            foreach(var name in new[]{"individual","cohorts"}) {
                var count=counts.GetProperty(name);long total=count.GetProperty("total").GetInt64();if(total<0 || count.GetProperty("has_more").GetBoolean()!=(total>50))throw new FormatException();
            }
            selection["variant"]=variant;
        } else {
            if(candidate.GetProperty("root_limit").GetBoolean())return selection;
            for(int i=0;i<roots.Length;i++) {
                if(!ReportScheduleAccess.FileRoot(owner,roots[i],"view"))continue;selected.Add(i);
                var root=roots[i];var resource=new AccessResource("file-audit"){PluginId="sli.file-audit",DeviceId=root.GetProperty("agent_id").GetString(),SourceInstanceId=root.GetProperty("source_instance_id").GetString(),CollectionScopeId=root.GetProperty("collection_scope_id").GetString()};
                if(dependency is not null && ResourceAccessDecisions.ReportAction(dependency,"security.queue","view",[[resource]],new HashSet<string>{"security"}).Allowed)qw.Add(i);
            }
            selection["root_indexes"]=JsonSerializer.SerializeToNode(selected);selection["qw_root_indexes"]=JsonSerializer.SerializeToNode(qw);
            if(selected.Count==0)return selection;
        }
        selection["include_count"]=recipients.Append(ownerId).Distinct().All(id=>actors.TryGetValue(id,out var access) && ReportScheduleAccess.Report(access,key) && ReportScheduleAccess.Report(access,key,"export") && selected.All(i=>ReportScheduleAccess.FileRoot(access,roots[i],"view") && ReportScheduleAccess.FileRoot(access,roots[i],"export")));
        return selection;
    }
}
public sealed record ReportScheduleClaim(Guid Id,Guid Lease,JsonElement Schedule,DateTimeOffset Evaluated,DateTimeOffset Slot,DateTimeOffset Start);
public interface IReportProducerBackend
{
    Task<Guid?> LeadAsync(Guid? leader,CancellationToken ct);
    Task<IReadOnlyList<ReportScheduleClaim>> ClaimAsync(Guid leader,CancellationToken ct);
    Task<JsonElement> FactsAsync(ReportScheduleClaim claim,CancellationToken ct);
    Task<JsonElement> CandidatesAsync(ReportScheduleClaim claim,CancellationToken ct);
    Task FailureAsync(ReportScheduleClaim claim,CancellationToken ct);
    Task<bool> PublishAsync(ReportScheduleClaim claim,JsonObject selection,CancellationToken ct);
}
public sealed record ReportProducerOutcome(Guid? Leader,string State,int Published);
public sealed class ReportScheduleProducer(IReportProducerBackend backend)
{
    public async Task<ReportProducerOutcome> TickAsync(Guid? leader,CancellationToken ct)
    {
        var stoppingToken=ct;
        using var budget=CancellationTokenSource.CreateLinkedTokenSource(ct);budget.CancelAfter(TimeSpan.FromSeconds(20));ct=budget.Token;int published=0;string state="ok";
        try {
            leader=await backend.LeadAsync(leader,ct);if(leader is null)return new(null,"standby",0);
            var claims=await backend.ClaimAsync(leader.Value,ct);if(claims.Count>2)throw new FormatException();
            foreach(var claim in claims) {
                ct.ThrowIfCancellationRequested();
                try {
                    if(ReportScheduleCalendar.Latest(claim.Schedule,claim.Evaluated)!=claim.Slot || ReportScheduleCalendar.Start(claim.Schedule,claim.Slot)!=claim.Start)throw new FormatException("report_calendar_mismatch");
                    string key=claim.Schedule.GetProperty("report_key").GetString()!;
                    var snapshot=await backend.FactsAsync(claim,ct);var actors=new Dictionary<long,AccessDecision>();
                    if(snapshot.GetProperty("report_key").GetString()!=key || snapshot.GetProperty("schedule_revision").GetInt64()!=claim.Schedule.GetProperty("revision").GetInt64() || snapshot.GetProperty("owner_user_id").GetInt64()!=claim.Schedule.GetProperty("owner_user_id").GetInt64())throw new FormatException();
                    var rawActors=snapshot.GetProperty("actors").EnumerateArray().ToArray();if(rawActors.Length is <1 or >101)throw new FormatException();
                    var evaluated=snapshot.GetProperty("evaluated_at").GetDateTimeOffset();
                    foreach(var actor in rawActors)actors.Add(actor.GetProperty("subject").GetProperty("id").GetInt64(),ReportScheduleAuthority.Compose(actor,key,evaluated));
                    var bindings=snapshot.GetProperty("bindings").EnumerateArray().ToArray();if(bindings.Length>100)throw new FormatException();
                    var recipients=bindings.Select(b=>b.GetProperty("recipient_user_id").GetInt64()).ToArray();
                    AccessDecision? dependency=null;
                    if(key=="file-audit.mass-operations")dependency=ReportScheduleAuthority.Compose(snapshot.GetProperty("dependencies").GetProperty("security.queue"),"security.problems",evaluated);
                    JsonElement candidate;
                    try {candidate=await backend.CandidatesAsync(claim,ct);}
                    catch(Exception e) when(e is not OperationCanceledException){await backend.FailureAsync(claim,ct);candidate=await backend.CandidatesAsync(claim,ct);}
                    var selection=ReportScheduleProjection.Select(key,snapshot.GetProperty("owner_user_id").GetInt64(),actors,recipients,candidate,dependency);
                    try {if(await backend.PublishAsync(claim,selection,ct))published++;}
                    catch(PostgresException e) when(e.SqlState=="57014") {
                        await backend.FailureAsync(claim,ct);candidate=await backend.CandidatesAsync(claim,ct);selection=ReportScheduleProjection.Select(key,snapshot.GetProperty("owner_user_id").GetInt64(),actors,recipients,candidate,dependency);if(await backend.PublishAsync(claim,selection,ct))published++;
                    }
                }
                catch(PostgresException e) when(e.SqlState=="P7001"){return new(leader,"backpressure",published);}
                catch(OperationCanceledException){throw;}
                catch {state="failed";}
            }
            return new(leader,state,published);
        }
        catch(OperationCanceledException) when(ct.IsCancellationRequested){return new(leader,stoppingToken.IsCancellationRequested?"stopped":"failed",published);}
        catch {return new(leader,"failed",published);}
    }
}
public sealed class ReportProducerBackend(NpgsqlConnection db):IReportProducerBackend
{
    async Task<object?> Rpc(string sql,ReportScheduleClaim? claim,CancellationToken ct,Action<NpgsqlCommand>? parameters=null,int milliseconds=2000)
    {
        await using var tx=await db.BeginTransactionAsync(ct);
        await using(var bounds=new NpgsqlCommand("select set_config('statement_timeout',@time,true),set_config('lock_timeout','500ms',true)",db,tx)){bounds.Parameters.AddWithValue("time",milliseconds+"ms");await bounds.ExecuteNonQueryAsync(ct);}
        await using var cmd=new NpgsqlCommand(sql,db,tx);
        if(claim is not null){cmd.Parameters.AddWithValue("id",claim.Id);cmd.Parameters.AddWithValue("lease",claim.Lease);}parameters?.Invoke(cmd);
        object? result=await cmd.ExecuteScalarAsync(ct);await tx.CommitAsync(ct);return result;
    }
    public async Task<Guid?> LeadAsync(Guid? leader,CancellationToken ct)
    {var result=await Rpc("select public.report_producer_lead(@leader)",null,ct,c=>c.Parameters.AddWithValue("leader",NpgsqlDbType.Uuid,(object?)leader??DBNull.Value));return result is Guid id?id:null;}
    public async Task<IReadOnlyList<ReportScheduleClaim>> ClaimAsync(Guid leader,CancellationToken ct)
    {
        var raw=await Rpc("select coalesce(jsonb_agg(to_jsonb(c)),'[]'::jsonb) from public.report_schedule_claim(@leader,2) c",null,ct,c=>c.Parameters.AddWithValue("leader",leader),10000);
        using var json=JsonDocument.Parse((string)raw!);return json.RootElement.EnumerateArray().Select(r=>new ReportScheduleClaim(r.GetProperty("job_id").GetGuid(),r.GetProperty("lease").GetGuid(),r.GetProperty("schedule").Clone(),r.GetProperty("evaluated_at").GetDateTimeOffset(),r.GetProperty("slot").GetDateTimeOffset(),r.GetProperty("period_from").GetDateTimeOffset())).ToArray();
    }
    async Task<JsonElement> JsonRpc(string function,ReportScheduleClaim claim,CancellationToken ct)
    {using var json=JsonDocument.Parse((string)(await Rpc("select public."+function+"(@id,@lease)",claim,ct))!);return json.RootElement.Clone();}
    public Task<JsonElement> FactsAsync(ReportScheduleClaim claim,CancellationToken ct)=>JsonRpc("report_schedule_acl_facts",claim,ct);
    public Task<JsonElement> CandidatesAsync(ReportScheduleClaim claim,CancellationToken ct)=>JsonRpc("report_schedule_candidates",claim,ct);
    public async Task FailureAsync(ReportScheduleClaim claim,CancellationToken ct)=>_=await Rpc("select public.report_schedule_failure(@id,@lease,'error')",claim,ct);
    public async Task<bool> PublishAsync(ReportScheduleClaim claim,JsonObject selection,CancellationToken ct)
    {using var json=JsonDocument.Parse((string)(await Rpc("select public.report_schedule_publish(@id,@lease,@selection::jsonb)",claim,ct,c=>c.Parameters.AddWithValue("selection",selection.ToJsonString())))!);return json.RootElement.GetProperty("published").GetBoolean();}
}
public static class ReportProducerCommand
{
    public static bool Healthy(JsonElement row,DateTimeOffset now)
    {
        try {
            if(row.ValueKind!=JsonValueKind.Object || !new HashSet<string>{"pid","at","state"}.SetEquals(row.EnumerateObject().Select(p=>p.Name)))return false;
            double age=now.ToUnixTimeMilliseconds()/1000.0-row.GetProperty("at").GetDouble();
            return row.GetProperty("pid").TryGetInt32(out var pid) && pid>0 && row.GetProperty("state").GetString() is "ok" or "standby" or "backpressure" && age is >=0 and <=90;
        }catch(Exception e) when(e is JsonException or InvalidOperationException or KeyNotFoundException or FormatException){return false;}
    }
    static string StatusPath=>Environment.GetEnvironmentVariable("SLI_REPORT_PRODUCER_STATUS_FILE")??Path.Combine(Path.GetTempPath(),"report-producer.json");
    public static bool Configuration(Func<string,string?> get,Func<string,byte[]> read,out string? dsn)
    {
        dsn=null;
        string? file=get("SLI_REPORT_PRODUCER_PG_PASSWORD_FILE");
        if(string.IsNullOrEmpty(file) || !Path.IsPathFullyQualified(file) || !string.IsNullOrEmpty(get("SLI_REPORT_PRODUCER_PG_PASSWORD")))return false;
        byte[] Read(string path){var bytes=read(path);if(bytes.Length is <1 or >4096)throw new FormatException();var text=System.Text.Encoding.UTF8.GetString(bytes).TrimEnd('\r','\n');if(text.Contains('\r') || text.Contains('\n'))throw new FormatException();return bytes;}
        return GpoWorkerConfiguration.TryCreateNamed(get,Read,"SLI_REPORT_PRODUCER_PG_DSN","SLI_REPORT_PRODUCER_PG_PASSWORD","sli-report-producer",10,out dsn);
    }
    public static async Task<int> RunAsync(string[] args)
    {
        if(args.SequenceEqual(["--health"])) {
            try {using var json=JsonDocument.Parse(await File.ReadAllTextAsync(StatusPath));return Healthy(json.RootElement,DateTimeOffset.UtcNow)?0:1;}catch{return 1;}
        }
        if(args.Length>1 || args.Any(x=>x!="--once"))return 1;
        if(!Configuration(Environment.GetEnvironmentVariable,p=>{using var f=File.OpenRead(p);var bytes=new byte[4097];int n=0,k;while(n<bytes.Length && (k=f.Read(bytes,n,bytes.Length-n))>0)n+=k;return bytes[..n];},out var dsn))return 1;
        using var stop=new CancellationTokenSource();ConsoleCancelEventHandler cancel=(_,e)=>{e.Cancel=true;stop.Cancel();};Console.CancelKeyPress+=cancel;
        using var sig=System.Runtime.InteropServices.PosixSignalRegistration.Create(System.Runtime.InteropServices.PosixSignal.SIGTERM,c=>{c.Cancel=true;stop.Cancel();});
        try {
            await using var db=new NpgsqlConnection(dsn);await db.OpenAsync(stop.Token);await using(var role=new NpgsqlCommand("set role adlog_report_producer",db))await role.ExecuteNonQueryAsync(stop.Token);
            var producer=new ReportScheduleProducer(new ReportProducerBackend(db));Guid? leader=null;
            do {
                var result=await producer.TickAsync(leader,stop.Token);leader=result.Leader;if(result.State=="failed")return 1;
                if(result.State is "ok" or "standby" or "backpressure") {
                    string path=StatusPath;
                    string tmp=path+".tmp";await File.WriteAllTextAsync(tmp,JsonSerializer.Serialize(new {pid=Environment.ProcessId,at=DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()/1000.0,state=result.State}),CancellationToken.None);File.Move(tmp,path,true);
                }
                if(args.Length==1)break;await Task.Delay(3000,stop.Token);
            }while(!stop.IsCancellationRequested);return 0;
        }catch(OperationCanceledException) when(stop.IsCancellationRequested){return 0;}
        catch {return 1;}
        finally {Console.CancelKeyPress-=cancel;}
    }
}
