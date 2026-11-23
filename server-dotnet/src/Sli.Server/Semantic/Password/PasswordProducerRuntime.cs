using Npgsql;
using Sli.Server.Agents.SnapshotPublication;
using System.Text.Json.Nodes;
using System.CommandLine;
using Sli.Server.Semantic.Detections;
using Sli.Server.Hosting;

namespace Sli.Server.Semantic.Password;

// Explicit semantic-worker credentials only. SET ROLE sessions are never pooled.
public sealed class PasswordProducerRuntime : IAsyncDisposable
{
    internal NpgsqlDataSource DataSource {get;}
    internal PasswordProducerRuntime(NpgsqlDataSource dataSource)=>DataSource=dataSource;
    public static PasswordProducerRuntime? TryCreate()=>TryCreate(Environment.GetEnvironmentVariable,ReadBounded);
    internal static PasswordProducerRuntime? TryCreate(Func<string,string?> get,Func<string,byte[]> read)
    {
        try { return Create(get, read); } catch (ServerConfigurationException) { return null; }
    }
    internal static PasswordProducerRuntime Create(Func<string,string?> get,Func<string,byte[]> read)
    {
        string dsn=GpoWorkerConfiguration.CreateNamed(get,read,"ADLOG_SEMANTIC_WORKER_DSN","ADLOG_SEMANTIC_WORKER_PASSWORD","adlog_semantic_worker",0);
        try{var b=new NpgsqlConnectionStringBuilder(dsn){Pooling=false,Multiplexing=false,CommandTimeout=0,Options="-c statement_timeout=0 -c lock_timeout=0"};return new(new NpgsqlDataSourceBuilder(b.ConnectionString).Build());}
        catch(Exception e)when(e is ArgumentException or FormatException){throw new ServerConfigurationException("ADLOG_SEMANTIC_WORKER_DSN");}
    }
    internal static PasswordProducerRuntime Create() => Create(Environment.GetEnvironmentVariable, ReadBounded);
    private static byte[] ReadBounded(string path){using var file=File.OpenRead(path);byte[] bytes=new byte[65537];int count=0,n;while(count<bytes.Length&&(n=file.Read(bytes,count,bytes.Length-count))!=0)count+=n;if(count>65536)throw new ArgumentException();return bytes[..count];}
    public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
    {
        var db=await DataSource.OpenConnectionAsync(ct);
        try {
            await using(var role=new NpgsqlCommand("set role adlog_semantic_worker",db))await role.ExecuteNonQueryAsync(ct);
            await using var check=new NpgsqlCommand("""
                with recursive login_role as(select oid from pg_roles where rolname=session_user),
                granted_roles(role_oid,role_name) as(
                  select r.oid,r.rolname from login_role l join pg_auth_members m on m.member=l.oid join pg_roles r on r.oid=m.roleid
                  union select r.oid,r.rolname from granted_roles parent join pg_auth_members m on m.member=parent.role_oid join pg_roles r on r.oid=m.roleid)
                select current_user='adlog_semantic_worker'
                  and not(a.rolsuper or a.rolcreatedb or a.rolcreaterole or a.rolreplication or a.rolbypassrls
                    or l.rolsuper or l.rolcreatedb or l.rolcreaterole or l.rolreplication or l.rolbypassrls)
                  and not exists(select 1 from granted_roles where role_name<>'adlog_semantic_worker')
                  and not exists(select 1 from pg_class where relowner=l.oid)
                  and not exists(select 1 from pg_namespace where nspowner=l.oid)
                  and not exists(select 1 from pg_class c cross join lateral aclexplode(c.relacl) acl where acl.grantee=l.oid)
                  and not exists(select 1 from pg_namespace n cross join lateral aclexplode(n.nspacl) acl where acl.grantee=l.oid)
                  and not exists(select 1 from pg_proc p cross join lateral aclexplode(p.proacl) acl where acl.grantee=l.oid)
                from pg_roles a cross join pg_roles l where a.rolname=current_user and l.rolname=session_user
                """,db);
            if(await check.ExecuteScalarAsync(ct) is not true)throw new PasswordFailure("password_v2_worker_privilege_invalid");return db;
        }catch{await db.DisposeAsync();throw;}
    }
    internal async Task<NpgsqlConnection> OpenControlAsync(CancellationToken ct)
    {
        while (true) {
            try { return await OpenAsync(ct); }
            catch (Exception error) when (SemanticWork.ConnectionWait(error)) {
                Console.Error.WriteLine("semantic_control_waiting:database_connections_exhausted:53300:retry");
                await Task.Delay(1000, ct);
            }
        }
    }
    public ValueTask DisposeAsync()=>DataSource.DisposeAsync();
}

public sealed record PasswordProducerBatch(int Sources,int Committed,int Failed,int Disabled,int Jobs,int Skipped=0)
{
    public int Completed {get;init;}
    public JsonObject FailureReasons {get;init;} = new();
    public JsonObject ImportSummary {get;init;} = new();
}

public sealed class PasswordProducerPoller(PasswordProducerRuntime runtime,PasswordProducer producer,DetectionProducer detections)
{
    internal SemanticWork? Work { get; init; }
    internal TimeProvider Clock { get; init; } = TimeProvider.System;
    internal async Task<IReadOnlyList<PasswordProducerOutcome>> RunSourceAsync(PasswordScope scope,CancellationToken ct)
    {
        await using var db=await runtime.OpenAsync(ct);
        async Task<bool> SourceLock(bool acquire,CancellationToken token) {
            SemanticWork.Query(db,"password_producer_source382(");
            await using var command=new NpgsqlCommand("select public.password_producer_source382(@s::jsonb,@acquire)",db){CommandTimeout=0};
            command.Parameters.AddWithValue("s",scope.Document.ToJsonString());command.Parameters.AddWithValue("acquire",acquire);
            return await command.ExecuteScalarAsync(token) is true;
        }
        string step="password_producer_source382";
        try {
            if(!await SourceLock(true,ct))return [new(Failed:false,Status:"busy",Diagnostic:DetectionDiagnostics.Describe(new PasswordFailure("password_producer_busy"),step))];
            try {
                var caches=new Dictionary<string,Dictionary<long,PasswordNative>>();
                Task<PasswordProducerOutcome> Run(PasswordRule rule,CancellationToken token) {
                    if(!caches.TryGetValue(rule.Pin,out var cache))caches[rule.Pin]=cache=[];
                    return producer.RunAsync(db,rule,token,cache);
                }
                var live=new List<PasswordRule>();var catchup=new List<PasswordRule>();
                step="password_plan388";
                foreach(string kind in new[]{"brute","spray"}) {
                    var rule=new PasswordRule(scope,kind);
                    SemanticWork.Query(db,"password_plan388(");
                    await using var command=new NpgsqlCommand("select public.password_plan388(@s::jsonb,@r)::text",db){CommandTimeout=0};
                    command.Parameters.AddWithValue("s",scope.Document.ToJsonString());command.Parameters.AddWithValue("r",rule.Id);
                    var planned=await command.ExecuteScalarAsync(ct);
                    if(planned is null or DBNull)return [new(Failed:false,Status:"unconfigured")];
                    var plan=PasswordJson.Obj(JsonNode.Parse((string)planned));
                    live.Add(new(scope,kind,plan["live"]!["rule_version"]!.GetValue<int>()));
                    // One finite history slice per rule yields to live work on the
                    // next poll; there is no elapsed-time deadline for either pass.
                    if(plan["catchup"]!.AsArray().FirstOrDefault() is {} pending)
                        catchup.Add(new(scope,kind,pending["rule_version"]!.GetValue<int>()));
                }
                return await RunPassesAsync(live,catchup,Run,ct,Clock);
            } finally {
                if(db.FullState==System.Data.ConnectionState.Open)await SourceLock(false,CancellationToken.None);
            }
        } catch(PostgresException error) when(!ct.IsCancellationRequested) {
            var diagnostic=DetectionDiagnostics.Describe(error,step);
            return error.SqlState==PostgresErrorCodes.LockNotAvailable
                ? [new(Failed:false,Status:"busy",Diagnostic:diagnostic)] : [new(Diagnostic:diagnostic)];
        }
    }
    internal static async Task<IReadOnlyList<PasswordProducerOutcome>> RunPassesAsync(IReadOnlyList<PasswordRule> live,
        IReadOnlyList<PasswordRule> catchup,Func<PasswordRule,CancellationToken,Task<PasswordProducerOutcome>> run,CancellationToken ct,TimeProvider? clock=null)
    {
        var liveStatus=new Dictionary<string,PasswordProducerOutcome>();
        async Task<PasswordProducerOutcome> RunLive(PasswordRule rule,CancellationToken token)
        {
            var outcome=await run(rule,token);
            liveStatus[rule.Kind]=outcome;
            return outcome;
        }
        bool CanCatchUp(PasswordRule rule)=>liveStatus.TryGetValue(rule.Kind,out var outcome)
            && !outcome.Failed && outcome.Status=="committed";
        var results=(await RunBatchesAsync(live[0].Scope,RunLive,ct,rules:live,targetAge:TimeSpan.FromSeconds(120),clock:clock)).ToList();
        foreach(var rule in catchup) {
            if(!CanCatchUp(rule))continue;
            // Recheck both live rules before every history slice, including
            // the second rule after a potentially expensive first history COMMIT.
            var current=await RunBatchesAsync(rule.Scope,RunLive,ct,rules:live,targetAge:TimeSpan.FromSeconds(120),clock:clock);
            results.AddRange(current);
            if(!CanCatchUp(rule))continue;
            var result=await run(rule,ct);results.Add(result);
            SemanticWork.Progress(new JsonObject{["cursor"]=new JsonObject{["pass"]="catchup",["rule"]=rule.Kind,
                ["watermark"]=result.Work?["watermark"]?.DeepClone()},["heartbeat"]=SemanticJson.Stamp((clock??TimeProvider.System).GetUtcNow())});
        }
        return results;
    }
    internal static async Task<IReadOnlyList<PasswordProducerOutcome>> RunBatchesAsync(PasswordScope scope,
        Func<PasswordRule,CancellationToken,Task<PasswordProducerOutcome>> run,CancellationToken ct,Action<string>? write=null,
        IReadOnlyList<PasswordRule>? rules=null,TimeSpan? targetAge=null,TimeProvider? clock=null)
    {
        write??=Console.Error.WriteLine;
        var results=new List<PasswordProducerOutcome>();
        rules??=[new PasswordRule(scope),new PasswordRule(scope,"spray")];
        var pending=new bool[rules.Count];
        Array.Fill(pending,true);
        var retries=new int[rules.Count];
        var watermarks=new DateTimeOffset?[rules.Count];
        var timeProvider=clock??TimeProvider.System;
        var target=timeProvider.GetUtcNow()-(targetAge??TimeSpan.FromMinutes(12));
        // Each live sweep has a fixed target so an advancing clock cannot keep
        // history waiting. Successful batches continue while the cursor moves.
        while(pending.Any(p=>p))for(int i=0;i<rules.Count;i++) {
            if(!pending[i])continue;ct.ThrowIfCancellationRequested();
            var result=await run(rules[i],ct);results.Add(result);
            if(result.Diagnostic is {} detail)detail["rule_id"]=rules[i].Id;
            if(result.Failed&&result.Diagnostic is {} diagnostic)write("password_producer_batch_failed:"+diagnostic.ToJsonString());
            var watermark=result.Work?["watermark"] is {} mark ? PasswordJson.Time(mark) : (DateTimeOffset?)null;
            pending[i]=result.Failed||result.Status=="busy" ? ++retries[i]<4 :
                result.Status=="committed"&&watermark<target&&(watermarks[i] is null||watermark>watermarks[i]);
            if(watermark.HasValue)watermarks[i]=watermark;
            SemanticWork.Progress(new JsonObject{["cursor"]=new JsonObject{["rule"]=rules[i].Kind,["watermark"]=result.Work?["watermark"]?.DeepClone(),["batches"]=results.Count},["heartbeat"]=SemanticJson.Stamp(timeProvider.GetUtcNow())});
        }
        return results;
    }
    public async Task<PasswordProducerBatch> RunOnceAsync(CancellationToken ct,JsonArray? discovered=null)
    {
        var sources=new List<PasswordScope>();
        if(discovered is null) {
            await using var db=await runtime.OpenAsync(ct);
            if(Work is null)await DetectionProducer.RefreshImportSummary(db,ct);
            discovered=new JsonArray();await using var tx=await db.BeginTransactionAsync(ct);
            await using(var command=new NpgsqlCommand("select source from public.default_detection_sources()",db,tx))
            await using(var reader=await command.ExecuteReaderAsync(ct))while(await reader.ReadAsync(ct))discovered.Add(new JsonObject{["source"]=JsonNode.Parse(reader.GetString(0))});
            await tx.CommitAsync(ct);
        }
        foreach(var row in discovered) { var source=row!["source"]!;if(source["scope"]?["plugin_id"]?.GetValue<string>()!="sli.windows.ad-dc")continue;var scope=PasswordScope.Read(source["scope"]);scope.Validate();sources.Add(scope); }
        int committed=0,failed=0,disabled=0,jobs=0,skipped=0;var diagnostics=new DetectionDiagnostics();
        foreach(var scope in sources.Distinct()){ct.ThrowIfCancellationRequested();
            var results=Work is null ? await RunSourceAsync(scope,ct) : await Work.Run("password_source:"+PasswordJson.Hash(scope.Document),()=>RunSourceAsync(scope,ct),ct);
            if(results is null)continue;foreach(var result in results) {
                if(result.Work?["proof_budget"] is JsonObject proofBudget)
                    Console.Error.WriteLine("password_producer_reduced_slice:"+proofBudget.ToJsonString());
                if(result.Failed){failed++;if(result.Diagnostic is {} diagnostic)diagnostics.Add(diagnostic);else diagnostics.Add(new PasswordFailure("password_v2_outcome_invalid"));}else if(result.Status is "unconfigured" or "busy"){skipped++;if(result.Diagnostic is {} diagnostic)Console.Error.WriteLine("password_producer_cycle_skipped:"+diagnostic.ToJsonString());}else if(result.Status=="disabled")disabled++;else if(result.Status=="committed"){committed++;jobs+=result.Jobs;}else throw new PasswordFailure("password_v2_outcome_invalid");
            }
        }
        await using var detectionDb=await runtime.OpenAsync(ct);
        var detectionBatch=await detections.RunOnceAsync(detectionDb,ct,discovered,refreshImport:false);
        diagnostics.Write("password_producer");var reasons=diagnostics.Counts;foreach(var (key,value) in detectionBatch.FailureReasons)reasons[key]=(reasons[key]?.GetValue<int>()??0)+value!.GetValue<int>();
        return new(sources.Count+detectionBatch.Sources,committed,failed+detectionBatch.Failed,disabled,jobs+detectionBatch.Jobs,skipped){Completed=committed+detectionBatch.Completed,FailureReasons=reasons,ImportSummary=detectionBatch.ImportSummary};
    }
}

public sealed record PasswordProducerOptions(bool Once=false,int PollSeconds=10);

public sealed class PasswordProducerHostedService(PasswordProducerPoller poller,PasswordProducerOptions options,IHostApplicationLifetime lifetime,ILogger<PasswordProducerHostedService> logger):BackgroundService
{
    public int ExitCode {get;private set;}
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try {
            do {
                try{var result=await poller.RunOnceAsync(stoppingToken);ExitCode=result.Failed==0?0:1;logger.LogInformation("password_producer_cycle sources={Sources} committed={Committed} failed={Failed} disabled={Disabled} jobs={Jobs}",result.Sources,result.Committed,result.Failed,result.Disabled,result.Jobs);}
                catch(OperationCanceledException)when(stoppingToken.IsCancellationRequested){throw;}
                catch{ExitCode=1;logger.LogWarning("password_producer_cycle_failed");}
                if(options.Once)break;await Task.Delay(TimeSpan.FromSeconds(Math.Clamp(options.PollSeconds,1,300)),stoppingToken);
            }while(!stoppingToken.IsCancellationRequested);
        }catch(OperationCanceledException)when(stoppingToken.IsCancellationRequested){}
        finally{if(options.Once)lifetime.StopApplication();}
    }
}

public static class PasswordProducerHosting
{
    // Integration can register this in its worker composition without touching web Program.
    public static IServiceCollection AddPasswordProducer(this IServiceCollection services,PasswordProducerRuntime runtime,PasswordProducerOptions options)
    {
        services.AddSingleton(runtime);services.AddSingleton(options);services.AddSingleton<PasswordProducer>();services.AddSingleton<IdentityAttackProducer>();services.AddSingleton<AttackPrecursorProducer>();services.AddSingleton<DetectionProducer>();services.AddSingleton<PasswordProducerPoller>();services.AddSingleton<PasswordProducerHostedService>();services.AddHostedService(sp=>sp.GetRequiredService<PasswordProducerHostedService>());return services;
    }
}

public static class PasswordProducerCommand
{
    public static async Task<int> RunAsync(string[] args)
    {
        var once=new Option<bool>("--once");var poll=new Option<int>("--poll-seconds"){DefaultValueFactory=_=>10};var command=new RootCommand("Produce managed password brute-force v2 signals and risk jobs.");command.Options.Add(once);command.Options.Add(poll);
        command.SetAction(async(parse,ct)=>{
            await using var runtime=PasswordProducerRuntime.TryCreate();if(runtime==null){Console.Error.WriteLine("password_v2_worker_configuration_invalid");return 1;}
            var builder=Host.CreateApplicationBuilder(Array.Empty<string>());builder.Services.AddPasswordProducer(runtime,new(parse.GetValue(once),parse.GetValue(poll)));using var host=builder.Build();var service=host.Services.GetRequiredService<PasswordProducerHostedService>();await host.RunAsync(ct);return service.ExitCode;
        });
        var parsed=command.Parse(args,new ParserConfiguration{ResponseFileTokenReplacer=null});return await parsed.InvokeAsync(new InvocationConfiguration{EnableDefaultExceptionHandler=false});
    }
}
