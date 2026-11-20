using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Legacy;
using Sli.Server.Semantic;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Legacy;

public sealed partial class LegacyJobRuntimeTests
{
    private static LegacySettings Settings(string directory, params (string Key, string Value)[] items)
    {
        var values = new Dictionary<string,string?> { ["Sli:DataDirectory"] = directory,
            ["Sli:Legacy:SLI_LEGACY_COLLECTION_DISABLED"] = "0", ["Sli:Legacy:ADLOG_ACQUISITION_DISABLED"] = "1" };
        foreach (var (key, value) in items) values["Sli:Legacy:" + key] = value;
        return new(new ConfigurationBuilder().AddInMemoryCollection(values).Build());
    }
    private sealed class EnvironmentStub : ILegacyEnvironment
    {
        public int Reads;
        public JsonObject Guard = new() { ["collection_allowed"] = true, ["status"] = "ok" };
        public Task<string[]> TargetsAsync(CancellationToken ct) { Reads++; return Task.FromResult(new[] { "dc.example.test" }); }
        public Task<JsonObject> DiskGuardAsync(CancellationToken ct) { Reads++; return Task.FromResult((JsonObject)Guard.DeepClone()); }
        public Task<string?> CollectionBlockAsync(CancellationToken ct) { Reads++; return Task.FromResult<string?>(null); }
    }
    private sealed class Audit : ILegacyAudit
    {
        public readonly List<(string Action, string Status, JsonObject Job)> Rows = [];
        public Task AppendAsync(string action, string status, JsonObject job, CancellationToken ct) { Rows.Add((action,status,(JsonObject)job.DeepClone())); return Task.CompletedTask; }
    }
    private sealed class Analysis : ILegacyAnalysis
    {
        public int Calls;
        public bool Fail;
        public Task<LegacyReport> RenderAsync(long id, string[] servers, CancellationToken ct) {
            Calls++;
            if (Fail) throw new InvalidOperationException("test-analysis-error-private-data");
            return Task.FromResult(new LegacyReport("/reports/domain-security-overview.html", [new("domain-security-overview.html", "<html>verified test report</html>")]));
        }
    }
    private sealed class Connections : IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => throw new InvalidOperationException("unexpected database access");
    }
    private sealed class Acquisition : ILegacyAcquisition
    {
        public int Calls;
        public Func<LegacyJobInput, int, LegacyCollectionBatch>? Next;
        public Task<LegacyCollectionBatch> CollectAsync(LegacyJobInput input, CancellationToken ct) {
            ct.ThrowIfCancellationRequested(); Calls++;
            return Task.FromResult(Next?.Invoke(input, Calls) ?? throw new InvalidOperationException("unexpected acquisition"));
        }
    }
    private sealed class Posts : ILegacyPostStore
    {
        public readonly Queue<LegacyPostClaim> Claims = new();
        public int Recoveries, Finishes, Failures, Published, FindingsWarnings;
        public bool Owns = true, LeaseLostOnFindings, FailFindingsWrite, FailFinishWrite;
        public bool FailQueue;
        public readonly List<(string DurableId, int SourceId, string[] Servers)> Queued = [];
        public string? Phase;
        public JsonObject? Findings;
        public Task QueueAsync(string durableId, int sourceId, string[] servers, CancellationToken ct) {
            if (FailQueue) throw new IOException("private-test-queue-error");
            Queued.Add((durableId, sourceId, servers)); return Task.CompletedTask;
        }
        public Task RecoverAsync(CancellationToken ct) { Recoveries++; return Task.CompletedTask; }
        public Task<IReadOnlyList<LegacyPostClaim>> ClaimAsync(string worker, int limit, CancellationToken ct) => Task.FromResult<IReadOnlyList<LegacyPostClaim>>(Claims.Count == 0 ? [] : [Claims.Dequeue()]);
        public Task HeartbeatAsync(LegacyPostClaim claim, string phase, CancellationToken ct) { Phase=phase; return Task.CompletedTask; }
        public Task FindingsAsync(LegacyPostClaim claim, JsonObject result, string? errorId, CancellationToken ct) {
            if (FailFindingsWrite) throw new IOException("durable findings update failed");
            Findings = (JsonObject)result.DeepClone();
            if (LeaseLostOnFindings) throw new LegacyLeaseLost(); if (errorId is not null) FindingsWarnings++; return Task.CompletedTask;
        }
        public Task FinishAsync(LegacyPostClaim claim, string? reportPath, string? errorId, CancellationToken ct) {
            if (FailFinishWrite) throw new IOException("durable job update failed");
            if (errorId is null) Finishes++; else Failures++; return Task.CompletedTask;
        }
        public async Task FenceAsync(LegacyPostClaim claim, Func<Task> publish, CancellationToken ct) {
            if (!Owns) throw new LegacyLeaseLost(); await publish(); Published++;
        }
    }
    private sealed class DirectoryScope : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "sli-legacy-tests-" + Guid.NewGuid().ToString("N"));
        public DirectoryScope() => Directory.CreateDirectory(Path);
        public void Dispose() => Directory.Delete(Path, true);
    }
    private static LegacyPostClaim Claim(int id=1) => new(Guid.NewGuid().ToString("N"),id,["dc.example.test"],"test-worker",1);

    [Fact] public async Task LegacyCutoverBlocksBeforeTargetsDiskAuditOrJobCreation()
    {
        using var dir = new DirectoryScope(); var environment = new EnvironmentStub(); var audit = new Audit(); var store = new LegacyJobStore();
        var jobs = new LegacyJobs(store,new(),Settings(dir.Path,("SLI_LEGACY_COLLECTION_DISABLED","typo")),environment,audit);
        var result = await jobs.CreateAsync(true,new([],1,200),TestContext.Current.CancellationToken);
        Assert.Equal("blocked",result["status"]!.GetValue<string>()); Assert.Equal("legacy_collection_disabled",result["reason"]!.GetValue<string>());
        Assert.False(result["collection_allowed"]!.GetValue<bool>()); Assert.Equal(0,environment.Reads); Assert.Empty(audit.Rows); Assert.Empty(store.List());
    }
    [Theory] [InlineData("disk_pressure_guard","skipped")] [InlineData("collection_guard_error","blocked")]
    public async Task DiskRejectionHasNoIdAndAuditsBeforeScheduling(string reason,string status)
    {
        using var dir = new DirectoryScope(); var environment = new EnvironmentStub { Guard = new() { ["collection_allowed"]=false,["reason"]=reason,["status"]="blocked" } };
        var audit = new Audit(); var store = new LegacyJobStore(); var jobs = new LegacyJobs(store,new(),Settings(dir.Path),environment,audit);
        var result = await jobs.CreateAsync(true,new([],3,400),TestContext.Current.CancellationToken);
        Assert.False(result.ContainsKey("id")); Assert.Equal(status,result["status"]!.GetValue<string>()); Assert.Equal("admission",result["phase"]!.GetValue<string>());
        Assert.Single(audit.Rows); Assert.Equal("manual_collection_start",audit.Rows[0].Action); Assert.Equal(status,audit.Rows[0].Status);
        Assert.Equal(2,environment.Reads); Assert.Empty(store.List());
    }
    [Fact] public async Task AcquisitionGuardKeepsFullJobShapeAndAudit()
    {
        using var dir = new DirectoryScope(); var environment = new EnvironmentStub(); var audit = new Audit(); var store = new LegacyJobStore();
        var result = await new LegacyJobs(store,new(),Settings(dir.Path),environment,audit).CreateAsync(true,new([],2,300),TestContext.Current.CancellationToken);
        Assert.Equal("skipped",result["status"]!.GetValue<string>()); Assert.Equal("acquisition_disabled",result["skipped_reason"]!.GetValue<string>());
        Assert.Equal("runtime_guard",result["mode"]!.GetValue<string>()); Assert.Equal(1,result["id"]!.GetValue<int>());
        foreach (string field in new[] { "analysis_report_url","report_url","duration_ms","analysis_error_id","findings_result","findings_error_id","current_channel" })
            Assert.True(result.ContainsKey(field) && result[field] is null);
        foreach (string field in new[] { "errors","warnings","servers","failed_servers","channels_in_progress","command_outputs" }) Assert.IsType<JsonArray>(result[field]);
        Assert.Equal("dc.example.test",result["servers"]![0]!.GetValue<string>()); Assert.Equal("skipped",Assert.Single(audit.Rows).Status);
    }
    [Fact] public async Task AnalysisRemainsUsableWithLegacyAcquisitionDisabled()
    {
        using var dir = new DirectoryScope(); var environment = new EnvironmentStub(); var audit = new Audit(); var store = new LegacyJobStore(); var queue = new LegacyWorkQueue();
        var settings = Settings(dir.Path,("SLI_LEGACY_COLLECTION_DISABLED","1"));
        var accepted = await new LegacyJobs(store,queue,settings,environment,audit).CreateAsync(false,new([],0,0),TestContext.Current.CancellationToken);
        Assert.Equal("queued",accepted["status"]!.GetValue<string>());
        await using var reader = queue.ReadAsync(TestContext.Current.CancellationToken).GetAsyncEnumerator(TestContext.Current.CancellationToken); Assert.True(await reader.MoveNextAsync());
        var acquisition = new Acquisition(); var analysis = new Analysis();
        await new LegacyJobExecution(store,settings,environment,analysis,acquisition,new Posts(),new Connections(),NullLogger<LegacyJobExecution>.Instance)
            .RunAsync(reader.Current,TestContext.Current.CancellationToken);
        var result = store.Get(accepted["id"]!.GetValue<int>())!;
        Assert.Equal("completed",result["status"]!.GetValue<string>()); Assert.Equal("/reports/domain-security-overview.html",result["analysis_report_url"]!.GetValue<string>());
        Assert.True(File.Exists(System.IO.Path.Combine(dir.Path,"reports","domain-security-overview.html"))); Assert.Equal(0,acquisition.Calls); Assert.Empty(audit.Rows);
    }
    [Fact] public async Task AnalysisFailureDoesNotLeakDiagnosticOrPublishSuccess()
    {
        using var dir = new DirectoryScope(); var store = new LegacyJobStore(); var input = new LegacyJobInput(["dc.example.test"],0,0);
        var job = store.Create("analyze_existing_events:manual",input);
        await new LegacyJobExecution(store,Settings(dir.Path),new EnvironmentStub(),new Analysis { Fail=true },new Acquisition(),new Posts(),new Connections(),NullLogger<LegacyJobExecution>.Instance)
            .RunAsync(new(job["id"]!.GetValue<int>(),false,input),TestContext.Current.CancellationToken);
        var result = store.Get(1)!; Assert.Equal("failed",result["status"]!.GetValue<string>()); Assert.Null(result["analysis_report_url"]);
        Assert.DoesNotContain("private-data",result.ToJsonString()); Assert.False(Directory.Exists(System.IO.Path.Combine(dir.Path,"reports")));
    }
    [Fact] public void StoreSnapshotsCannotMutateRetainedJobs()
    {
        var store = new LegacyJobStore(); var job = store.Create("analyze_existing_events:manual",new(["dc.example.test"],0,0)); job["status"]="forged";
        var snapshot = store.Get(1)!; snapshot["servers"]!.AsArray().Clear();
        Assert.Equal("queued",store.Get(1)!["status"]!.GetValue<string>()); Assert.Single(store.Get(1)!["servers"]!.AsArray());
    }
    [Fact] public async Task ExpiredOwnerCannotReplaceArtifactOrMarkCompleted()
    {
        using var dir = new DirectoryScope(); Directory.CreateDirectory(System.IO.Path.Combine(dir.Path,"reports"));
        string target = System.IO.Path.Combine(dir.Path,"reports","domain-security-overview.html"); File.WriteAllText(target,"previous owner");
        var posts = new Posts { Owns=false }; posts.Claims.Enqueue(Claim());
        var result = await new LegacyPostCollection(posts,new Analysis(),Settings(dir.Path),NullLogger<LegacyPostCollection>.Instance)
            .RunOnceAsync("test-worker",1,TestContext.Current.CancellationToken);
        Assert.Equal(new LegacyPostResult(1,0,1),result); Assert.Equal("previous owner",File.ReadAllText(target)); Assert.Equal(0,posts.Finishes);
        Assert.Empty(Directory.GetFiles(System.IO.Path.Combine(dir.Path,"reports"),"*.tmp"));
    }
    [Fact] public async Task LeaseLossDuringFindingsStopsBeforeAnalysis()
    {
        using var dir = new DirectoryScope(); var posts = new Posts { LeaseLostOnFindings=true }; posts.Claims.Enqueue(Claim()); var analysis = new Analysis();
        var result = await new LegacyPostCollection(posts,analysis,Settings(dir.Path),NullLogger<LegacyPostCollection>.Instance).RunOnceAsync("test-worker",1,TestContext.Current.CancellationToken);
        Assert.Equal(1,result.Failed); Assert.Equal(0,analysis.Calls); Assert.Equal(0,posts.Published); Assert.Equal(0,posts.Finishes);
    }
    [Fact] public async Task FindingsFailureIsIsolatedAndReportRemainsFenced()
    {
        using var dir = new DirectoryScope(); var posts = new Posts(); posts.Claims.Enqueue(Claim());
        var result = await new LegacyPostCollection(posts,new Analysis(),Settings(dir.Path,("ADLOG_LEGACY_FINDINGS_ENABLED","1")),NullLogger<LegacyPostCollection>.Instance)
            .RunOnceAsync("test-worker",1,TestContext.Current.CancellationToken);
        Assert.Equal(new LegacyPostResult(1,1,0),result); Assert.Equal(1,posts.FindingsWarnings); Assert.Equal(1,posts.Published); Assert.Equal(1,posts.Finishes);
    }
    [Fact] public async Task PostCollectionPreservesPartialCollectionAndUpdatesItsLocalAnalysis()
    {
        using var dir = new DirectoryScope(); var posts = new Posts(); var jobs = new LegacyJobStore();
        var job = jobs.Create("collect_all_dc_logs:manual",new(["dc.example.test"],1,200));
        jobs.Update(1,j=>{ j["status"]="partial"; j["collection_status"]="partial"; j["analysis_status"]="queued"; });
        posts.Claims.Enqueue(new(job["durable_id"]!.GetValue<string>(),1,["dc.example.test"],"test-worker",1));
        var result = await new LegacyPostCollection(posts,new Analysis(),Settings(dir.Path),NullLogger<LegacyPostCollection>.Instance,jobs)
            .RunOnceAsync("test-worker",1,TestContext.Current.CancellationToken);
        Assert.Equal(1,result.Completed); var updated = jobs.Get(1)!;
        Assert.Equal("partial",updated["status"]!.GetValue<string>()); Assert.Equal("partial",updated["collection_status"]!.GetValue<string>());
        Assert.Equal("completed",updated["analysis_status"]!.GetValue<string>()); Assert.Equal("completed",updated["report_status"]!.GetValue<string>());
        Assert.Equal("/reports/domain-security-overview.html",updated["analysis_report_url"]!.GetValue<string>()); Assert.NotNull(updated["analysis_finished_at"]);
    }
    [Fact] public async Task ResumingForeignDurableJobDoesNotOverwriteLocalJobWithSameNumericSourceId()
    {
        using var dir = new DirectoryScope(); var posts = new Posts(); var jobs = new LegacyJobStore();
        jobs.Create("analyze_existing_events:manual",new(["dc.example.test"],0,0)); var claim=Claim(); posts.Claims.Enqueue(claim);
        await new LegacyPostCollection(posts,new Analysis(),Settings(dir.Path),NullLogger<LegacyPostCollection>.Instance,jobs)
            .RunOnceAsync("test-worker",1,TestContext.Current.CancellationToken);
        Assert.Equal("queued",jobs.Get(1)!["status"]!.GetValue<string>()); Assert.Equal(2,jobs.List().Count);
        Assert.Equal(claim.DurableId,jobs.Get(2)!["durable_id"]!.GetValue<string>()); Assert.Equal("completed",jobs.Get(2)!["analysis_status"]!.GetValue<string>());
    }
    [Fact] public async Task PostCollectionDisabledDoesNotRecoverOrClaimLegacyJobs()
    {
        using var dir = new DirectoryScope(); var posts = new Posts(); posts.Claims.Enqueue(Claim());
        var result = await new LegacyPostCollection(posts,new Analysis(),Settings(dir.Path,("SLI_LEGACY_COLLECTION_DISABLED","1")),NullLogger<LegacyPostCollection>.Instance)
            .RunOnceAsync("test-worker",1,TestContext.Current.CancellationToken);
        Assert.Equal(new LegacyPostResult(0,0,0),result); Assert.Equal(0,posts.Recoveries); Assert.Single(posts.Claims);
    }
    [Theory] [InlineData("completed")] [InlineData("partial")]
    public async Task ReportFailureIsDurableAndPreservesCollectionStatus(string collectionStatus)
    {
        using var dir = new DirectoryScope(); var posts = new Posts(); var jobs = new LegacyJobStore();
        var job = jobs.Create("collect_all_dc_logs:scheduled",new(["dc.example.test"],1,1000));
        jobs.Update(1,j => { j["status"] = collectionStatus; j["collection_status"] = collectionStatus; j["analysis_status"] = "queued"; });
        posts.Claims.Enqueue(new(job["durable_id"]!.GetValue<string>(),1,["dc.example.test"],"test-worker",1));
        var result = await new LegacyPostCollection(posts,new Analysis { Fail=true },Settings(dir.Path),NullLogger<LegacyPostCollection>.Instance,jobs)
            .RunOnceAsync("test-worker",1,TestContext.Current.CancellationToken);
        Assert.Equal(new LegacyPostResult(1,0,1),result); Assert.Equal(1,posts.Failures); Assert.Equal(0,posts.Published);
        var updated = jobs.Get(1)!;
        Assert.Equal(collectionStatus,(string?)updated["status"]); Assert.Equal(collectionStatus,(string?)updated["collection_status"]);
        Assert.Equal("failed",(string?)updated["analysis_status"]); Assert.Equal("failed",(string?)updated["report_status"]);
        Assert.StartsWith("post_collection_failed_",(string?)updated["analysis_error_id"]);
        Assert.NotNull(updated["analysis_finished_at"]); Assert.Null(updated["analysis_report_url"]);
        Assert.Empty(updated["errors"]!.AsArray()); Assert.DoesNotContain("private-data",updated.ToJsonString());
        Assert.False(Directory.Exists(System.IO.Path.Combine(dir.Path,"reports")));
    }

    // Acquisition reports normalized outcomes in .NET: Python return code 0,
    // code 0 + partial marker, code 4, and code 1 map to these four inputs.
    [Theory]
    [InlineData("completed",null,"completed",true)]
    [InlineData("partial",null,"partial",true)]
    [InlineData("partial","successful channels imported","partial",true)]
    [InlineData("failed",null,"failed",false)]
    public async Task CollectionCycleQueuesOnlySuccessfulOrPartialResultsWithoutInlineAnalysis(
        string batchStatus,string? warning,string expectedStatus,bool queued)
    {
        using var dir = new DirectoryScope(); var jobs = new LegacyJobStore(); var posts = new Posts(); var analysis = new Analysis { Fail = true };
        var input = new LegacyJobInput(["dc.example.test"],1,1000);
        jobs.Create("collect_all_dc_logs:scheduled",input);
        var acquisition = new Acquisition { Next = (_,_) => new(batchStatus,[],10,Warnings: warning is null ? null : [warning]) };
        var execution = new LegacyJobExecution(jobs,Settings(dir.Path,("ADLOG_CONTINUOUS_RECOVERY","0"),("ADLOG_SCHEDULER_SKIP_REPORT","0")),
            new EnvironmentStub(),analysis,acquisition,posts,new Connections(),NullLogger<LegacyJobExecution>.Instance);
        await execution.CollectBodyAsync(new(1,true,input),TestContext.Current.CancellationToken);
        var result = jobs.Get(1)!;
        Assert.Equal(expectedStatus,(string?)result["status"]); Assert.Equal(expectedStatus,(string?)result["collection_status"]);
        Assert.Equal(10L,result["events_collected"]!.GetValue<long>()); Assert.Equal(1,acquisition.Calls);
        Assert.Equal(queued ? "queued" : "not_queued",(string?)result["analysis_status"]);
        Assert.Equal(queued ? "queued" : "not_queued",(string?)result["report_status"]);
        Assert.Equal(queued ? "analysis_queued" : "done",(string?)result["phase"]);
        Assert.Equal(0,analysis.Calls); Assert.False(Directory.Exists(System.IO.Path.Combine(dir.Path,"reports")));
        if (queued) {
            var row = Assert.Single(posts.Queued);
            Assert.Equal((string?)result["durable_id"],row.DurableId); Assert.Equal(1,row.SourceId); Assert.Equal(input.Servers,row.Servers);
        } else Assert.Empty(posts.Queued);
        if (expectedStatus == "partial") { Assert.NotEmpty(result["warnings"]!.AsArray()); Assert.Empty(result["errors"]!.AsArray()); }
        else if (expectedStatus == "failed") Assert.NotEmpty(result["errors"]!.AsArray());
        else { Assert.Empty(result["warnings"]!.AsArray()); Assert.Empty(result["errors"]!.AsArray()); }
    }

    [Fact] public async Task RecoveryContinuesPastObsoleteCycleBudgetUntilSourceBoundary()
    {
        using var dir = new DirectoryScope(); var jobs = new LegacyJobStore(); var posts = new Posts(); var analysis = new Analysis();
        var input = new LegacyJobInput(["dc.example.test","other.example.test"],1,1000);
        jobs.Create("collect_all_dc_logs:scheduled",input);
        var acquisition = new Acquisition { Next = (current,cycle) => {
            Assert.Equal(cycle == 1 ? input.Servers : ["dc.example.test"],current.Servers);
            Assert.Equal(cycle,jobs.Get(1)!["cycle"]!.GetValue<int>());
            Assert.Equal("running",(string?)jobs.Get(1)!["status"]);
            Assert.Empty(posts.Queued);
            return new("completed",cycle < 3 ? ["dc.example.test"] : [],50000);
        } };
        var settings = Settings(dir.Path,("ADLOG_CONTINUOUS_RECOVERY","1"),("ADLOG_CONTINUOUS_RECOVERY_MAX_CYCLES","1"),
            ("ADLOG_CONTINUOUS_RECOVERY_MAX_JOB_SECONDS","60"),("ADLOG_CONTINUOUS_RECOVERY_COOLDOWN_SECONDS","0"),("ADLOG_SCHEDULER_SKIP_REPORT","0"));
        await new LegacyJobExecution(jobs,settings,new EnvironmentStub(),analysis,acquisition,posts,new Connections(),NullLogger<LegacyJobExecution>.Instance)
            .CollectBodyAsync(new(1,true,input),TestContext.Current.CancellationToken);
        var result = jobs.Get(1)!;
        Assert.Equal(3,acquisition.Calls); Assert.Equal(150000L,result["events_collected"]!.GetValue<long>());
        Assert.Equal("completed",(string?)result["status"]); Assert.Empty(result["errors"]!.AsArray()); Assert.Empty(result["warnings"]!.AsArray());
        Assert.Equal("queued",(string?)result["analysis_status"]); Assert.Equal(input.Servers,Assert.Single(posts.Queued).Servers); Assert.Equal(0,analysis.Calls);
    }

    [Fact] public async Task QueueFailureCannotUndoCompletedCollection()
    {
        using var dir = new DirectoryScope(); var jobs = new LegacyJobStore(); var posts = new Posts { FailQueue = true };
        var input = new LegacyJobInput(["dc.example.test"],1,1000); jobs.Create("collect_all_dc_logs:scheduled",input);
        await new LegacyJobExecution(jobs,Settings(dir.Path,("ADLOG_SCHEDULER_SKIP_REPORT","0")),new EnvironmentStub(),new Analysis(),
            new Acquisition { Next = (_,_) => new("completed",[],10) },posts,new Connections(),NullLogger<LegacyJobExecution>.Instance)
            .CollectBodyAsync(new(1,true,input),TestContext.Current.CancellationToken);
        var result = jobs.Get(1)!;
        Assert.Equal("completed",(string?)result["status"]); Assert.Equal("completed",(string?)result["collection_status"]);
        Assert.Equal("failed",(string?)result["analysis_status"]); Assert.Equal("post_collection_queue_failed",(string?)result["analysis_error_id"]);
        Assert.Empty(result["errors"]!.AsArray()); Assert.DoesNotContain("private-test-queue-error",result.ToJsonString());
    }

    private sealed class PostConnections(PostCollectionPostgres pg) : IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => pg.OpenAsync(ct);
    }

    [Fact] public async Task DurableQueueDeduplicatesAndWorkerStandsDownForClaimedRow()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var pg = new PostCollectionPostgres(canonicalSchema:true); await pg.StartAsync(ct);
        await using var db = await pg.OpenAsync(ct);
        string schema = await File.ReadAllTextAsync(System.IO.Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_schema_v8.sql"),ct);
        string table = System.Text.RegularExpressions.Regex.Match(schema,@"create table if not exists post_collection_jobs \([\s\S]*?\r?\n\);").Value;
        Assert.NotEmpty(table); await PostCollectionPostgres.Sql(db,table,ct);
        await PostCollectionLeasePostgresTests.AuthorizeAsync(pg,ct);
        var posts = new LegacyPostStore(new PostConnections(pg)); const string id = "runtime-902";
        await Task.WhenAll(posts.QueueAsync(id,902,["dc.example.test"],ct),posts.QueueAsync(id,902,["dc.example.test"],ct));
        await using (var count = new NpgsqlCommand("select count(*) from post_collection_jobs",db)) Assert.Equal(1L,await count.ExecuteScalarAsync(ct));
        var owners = await Task.WhenAll(posts.ClaimAsync("first-worker",1,ct),posts.ClaimAsync("second-worker",1,ct));
        var claim = Assert.Single(owners.SelectMany(x=>x));
        Assert.Equal(id,claim.DurableId); Assert.Equal(902,claim.SourceId); Assert.Equal(["dc.example.test"],claim.Servers); Assert.Equal(1,claim.Attempt);
        await posts.QueueAsync(id,999,["other.example.test"],ct);
        var analysis = new Analysis(); var jobs = new LegacyJobStore();
        var result = await new LegacyPostCollection(posts,analysis,Settings(pg.Root),NullLogger<LegacyPostCollection>.Instance,jobs)
            .RunOnceAsync("third-worker",1,ct);
        Assert.Equal(new LegacyPostResult(0,0,0),result); Assert.Equal(0,analysis.Calls); Assert.Empty(jobs.List());
        await using (var state = new NpgsqlCommand("select status,worker_id,attempt_count,source_job_id,servers_json::text from post_collection_jobs",db)) {
            await using var reader = await state.ExecuteReaderAsync(ct); Assert.True(await reader.ReadAsync(ct));
            Assert.Equal("running",reader.GetString(0)); Assert.Equal(claim.Worker,reader.GetString(1)); Assert.Equal(1,reader.GetInt32(2));
            Assert.Equal(902,reader.GetInt64(3)); Assert.Equal(["dc.example.test"],JsonSerializer.Deserialize<string[]>(reader.GetString(4))!);
            Assert.False(await reader.ReadAsync(ct));
        }
        Assert.DoesNotContain("ERROR:",await pg.DiagnosticsAsync(ct));
    }
    [Fact] public async Task TraversalArtifactIsRejectedBeforeAnyPublication()
    {
        using var dir = new DirectoryScope();
        await Assert.ThrowsAsync<InvalidDataException>(()=>LegacyReportPublication.PublishAsync(new("/reports/x.html",[new("../x.html","injection")]),dir.Path,null,TestContext.Current.CancellationToken));
        Assert.Empty(Directory.GetFiles(dir.Path));
    }
    [Fact] public async Task CollectionCommandRejectsInvalidArgumentsWithoutStartingWeb()
    {
        Assert.NotEqual(0,await LegacyWorkerCommand.RunAsync("collection-worker",["--unknown-test-option"]));
    }
    [Theory]
    [InlineData("ADLOG_SEMANTIC_NORMALIZATION_ENABLED","0","semantic_normalization_must_be_explicitly_enabled")]
    [InlineData("ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED","1","semantic_directory_state_forbidden")]
    [InlineData("ADLOG_SEMANTIC_FINDING_CREATION_ENABLED","1","semantic_finding_creation_forbidden")]
    public void DevelopmentSemanticScopeFailsClosed(string key,string value,string code)
    {
        using var dir = new DirectoryScope();
        var settings=Settings(dir.Path,("ADLOG_SEMANTIC_NORMALIZATION_ENABLED","1"),("ADLOG_SEMANTIC_ASSEMBLY_ENABLED","1"),
            ("ADLOG_SEMANTIC_CORRELATION_ENABLED","1"),("ADLOG_SEMANTIC_RISK_ENGINE_ENABLED","1"),(key,value));
        Assert.Equal(code,Assert.Throws<InvalidOperationException>(()=>DevelopmentSemanticGuard.ValidateSettings(settings)).Message);
    }
    [Fact] public void DevelopmentSemanticTestShadowSettingsAreAccepted()
    {
        using var dir = new DirectoryScope(); DevelopmentSemanticGuard.ValidateSettings(Settings(dir.Path,("ADLOG_SEMANTIC_NORMALIZATION_ENABLED","1"),
            ("ADLOG_SEMANTIC_ASSEMBLY_ENABLED","1"),("ADLOG_SEMANTIC_CORRELATION_ENABLED","1"),("ADLOG_SEMANTIC_RISK_ENGINE_ENABLED","1"),
            ("ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED","0"),("ADLOG_SEMANTIC_FINDING_CREATION_ENABLED","0")));
    }

    [Fact] public async Task ReportPublicationRejectsDuplicateNamesBeforeOverwriting()
    {
        using var dir = new DirectoryScope();
        await Assert.ThrowsAsync<InvalidDataException>(() => LegacyReportPublication.PublishAsync(
            new("/reports/x.html", [new("x.html","first"),new("x.html","second")]), dir.Path, null,
            TestContext.Current.CancellationToken));
        Assert.Empty(Directory.GetFiles(dir.Path));
    }

    [Fact] public void EmptyReportKeepsThreatScoreUnavailableAndExplainsBlindSpots()
    {
        var context=LegacyReportContext.Build(23,["dc.example.test"],[],null,null,
            [("high","Нет событий по выбранному контроллеру домена","В PostgreSQL нет импортированных событий для этого DC. Анализ рисков по содержимому невозможен.","Проверить доступность DC.")],true);
        Assert.Null(context["risk_score"]); Assert.Equal(6,context["kpis"]!.AsArray().Count);
        Assert.Equal(19,context["coverage_rows"]!.AsArray().Count); Assert.Single(context["correlation_rows"]!.AsArray());
        Assert.All(context["findings"]!.AsArray(),x=>Assert.Equal("draft_only",x!["provenance"]!["authority"]!.GetValue<string>()));
        string html=LegacyReportTemplate.Render(context);
        Assert.Contains("Оценка угрозы недоступна",html); Assert.Contains("<div class=\"num\">—</div>",html);
        Assert.DoesNotContain("@@",html); Assert.Contains("id=\"eventTable\"",html); Assert.Contains("server-dc.example.test-security-profile.html",html);
    }

    [Fact] public void LegacyThreatScoreUsesOnlyObservedSecuritySignals()
    {
        Assert.Equal(35,LegacyReportContext.ThreatScore(100,
            new JsonArray(new JsonObject { ["risk"]="high" }),
            new JsonArray(new JsonObject { ["severity"]="medium" })));
    }

    [Fact] public void LegacyFindingCardsRemainDraftsDespiteClaimedRisk()
    {
        var correlations=new JsonArray(new JsonObject { ["risk"]="critical",["scenario"]="Test signal",
            ["facts"]="Observed",["meaning"]="Needs qualification",["recommendation"]="Review evidence" });
        var cards=LegacyReportContext.FindingCards(
            [("high","Test recommendation","Coverage hint","Review evidence")],correlations,[]);
        Assert.Equal(2,cards.Count);
        Assert.All(cards,card=> {
            Assert.Equal("unknown",card.Text("severity"));
            Assert.Equal("not_applicable",card.Text("confidence"));
            Assert.Equal("draft_only",card!["provenance"].Text("authority"));
        });
        Assert.Equal("Test signal",cards[0].Text("title"));
        Assert.Equal("Observed",cards[0].Text("facts"));
        Assert.Equal("Test recommendation",cards[1].Text("title"));
        Assert.Equal("Coverage hint",cards[1].Text("facts"));
    }

    [Fact] public void LegacyCorrelationDraftDoesNotAssertPolicyRiskOrConfidence()
    {
        var draft=LegacyReportContext.DraftFinding(new JsonObject { ["risk"]="critical",["scenario"]="Test signal",
            ["facts"]="Observed",["meaning"]="Needs qualification",["recommendation"]="Review evidence",
            ["confidence"]="high",["missing_data"]="Policy admission" });
        Assert.Equal("unknown",draft.Text("risk"));
        Assert.Equal("not_applicable",draft.Text("confidence"));
        Assert.Equal("draft_only",draft["provenance"].Text("authority"));
        Assert.Equal("Test signal",draft.Text("scenario"));
        Assert.Equal("Observed",draft.Text("facts"));
        Assert.Equal("Policy admission",draft.Text("missing_data"));
    }

    [Fact] public void ReportUsesCatalogProviderIdentityRiskKpisAndEncodedEvidence()
    {
        var context=LegacyReportContext.Build(23,["dc.example.test"],
            [new(1102,"Security","Microsoft-Windows-Eventlog",2),new(5504,"DNS Server","Microsoft-Windows-DNS-Server-Service",8)],
            "2026-11-01T00:00:00+00:00","2026-11-01T01:30:00+00:00",
            [("medium","DNS Server 5504","Проверить Event ID 5504","Проверить DNS")],true);
        Assert.Equal(10,context.Number("total_events"));
        Assert.Equal("80%",context["kpis"]![1]!["value"]!.GetValue<string>());
        Assert.Equal("1ч 30м",context["kpis"]![2]!["value"]!.GetValue<string>());
        Assert.Equal(2,context["event_rows"]!.AsArray().Count);
        var unknown=LegacyReportContext.Criticality(new(1102,"unrecognized channel","unrecognized provider",1));
        Assert.Equal("info",unknown.Text("severity")); Assert.Equal("gap",unknown.Text("catalog_status"));
        string html=LegacyReportTemplate.Render(context);
        Assert.Contains("Открыть события-доказательства",html); Assert.Contains("event_id=5504",html);
        Assert.Contains("Соседние события ±15 минут",html); Assert.Contains("function renderRows()",html);
    }

    [Fact] public void HostileReportStringsCannotCloseScriptInjectMarkupOrReplaceTemplateTokens()
    {
        const string hostile="</script><script>alert(23)</script><img src=x onerror=alert(23)> & \" ' \u2028\u2029 @@title@@";
        var context=LegacyReportContext.Build(23,["dc.example.test"],[new(9999,hostile,hostile,1)],null,null,[],true);
        string html=LegacyReportTemplate.Render(context);
        Assert.DoesNotContain("<script>alert(23)",html); Assert.DoesNotContain("<img src=x",html);
        Assert.Contains("\\u003C/script\\u003E",html); Assert.Contains("\\u2028",html); Assert.Contains("\\u2029",html);
        Assert.Contains("&lt;/script&gt;",html); Assert.Contains("@@title@@",html); // Source data is never a second template pass.
    }

    // Parity: tests/reporting/test_report_template_script_safety.py.
    [Fact] public void ReportEventRowsJsonIsSafeInsideHtmlScriptAndRoundTrips()
    {
        var rows = new JsonArray(
            new JsonObject {
                ["risk"] = "High", ["event_id"] = 1, ["channel"] = "Security",
                ["provider_name"] = "Provider", ["count"] = 1,
                ["description"] = "</script><script>alert(1)</script><!--\u2028\u2029",
                ["why"] = "reason", ["detail_url"] = "/events/1",
                ["action"] = "review", ["missing"] = "none"
            },
            new JsonObject {
                ["risk"] = "Info", ["event_id"] = 2, ["channel"] = "System",
                ["provider_name"] = "Benign Provider", ["count"] = 3,
                ["description"] = "ordinary text & symbols < >",
                ["why"] = "normal control", ["detail_url"] = "/events/2",
                ["action"] = "none", ["missing"] = "none"
            });
        var context = new JsonObject {
            ["title"] = "Security report", ["subtitle"] = "Test report", ["scope_name"] = "DC1",
            ["period_text"] = "test window", ["total_events"] = 2, ["main_noise"] = "none",
            ["coverage_status"] = "complete", ["analysis_mode"] = "local_rules_ai_layer",
            ["risk_score"] = 0, ["risk_note"] = "No risk", ["kpis"] = new JsonArray(),
            ["main_conclusion"] = "No findings", ["main_limitation"] = "Test fixture",
            ["channel_rows"] = new JsonArray(), ["actions"] = new JsonArray(),
            ["findings"] = new JsonArray(), ["coverage_rows"] = new JsonArray(),
            ["correlation_rows"] = new JsonArray(), ["event_rows"] = rows.DeepClone(),
            ["source_facts"] = new JsonArray(), ["assumptions"] = new JsonArray(),
            ["server_links"] = new JsonArray()
        };

        string html = LegacyReportTemplate.Render(context).Replace("\r\n", "\n");
        const string prefix = "const rows = ";
        int start = html.IndexOf(prefix, StringComparison.Ordinal);
        Assert.True(start >= 0, "The report must embed event rows in its script.");
        start += prefix.Length;
        int end = html.IndexOf(";\nfunction escapeHtml", start, StringComparison.Ordinal);
        Assert.True(end >= start, "The embedded rows must be followed by the rendering script.");
        string embedded = html[start..end];

        Assert.DoesNotContain("</script", embedded, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<!--", embedded);
        Assert.DoesNotContain("\u2028", embedded);
        Assert.DoesNotContain("\u2029", embedded);
        Assert.True(JsonNode.DeepEquals(rows, JsonNode.Parse(embedded)),
            "Script-safe JSON must preserve every field and type of both event rows.");
    }

    private sealed class FindingsDatabase : ISemanticDatabase
    {
        public readonly List<string> Sql=[];
        public JsonArray Events=[];
        public long Before=7,After=7;
        public int Commits;
        public bool FailBeforeWatermarkCommit;
        public Task<ISemanticSession> OpenAsync(bool write,CancellationToken ct)=>Task.FromResult<ISemanticSession>(new Session(this));
        private sealed class Session(FindingsDatabase owner) : ISemanticSession
        {
            private long? staged;
            public Task<JsonArray> QueryAsync(string sql,CancellationToken ct,params object?[] values)
            {
                ct.ThrowIfCancellationRequested(); owner.Sql.Add(sql);
                if(sql.StartsWith("select last_event_id",StringComparison.Ordinal)) return Task.FromResult(new JsonArray(new JsonObject { ["last_event_id"]=owner.Before }));
                if(sql.StartsWith("select id,event_id",StringComparison.Ordinal)) return Task.FromResult((JsonArray)owner.Events.DeepClone());
                if(sql.Contains("set last_event_id=$2",StringComparison.Ordinal)) staged=(long)values[1]!;
                return Task.FromResult(new JsonArray());
            }
            public Task CommitAsync(CancellationToken ct) {
                if (staged is not null && owner.FailBeforeWatermarkCommit) throw new IOException("before commit");
                owner.Commits++; if(staged is {} after)owner.After=after;return Task.CompletedTask;
            }
            public ValueTask DisposeAsync()=>ValueTask.CompletedTask;
        }
    }
    [Fact] public async Task EmptyPostgresFindingsReadHasNoLegacyBackendLimitations()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var postgres = new Sli.Server.Tests.Agents.PostCollectionPostgres(canonicalSchema: true);
        await postgres.StartAsync(ct);
        await using (var db = await postgres.OpenAsync(ct))
            await Sli.Server.Tests.Agents.PostCollectionPostgres.Sql(db, """
                create table findings_active(title text,actor text,target text,source text,summary text,
                    severity text,status text,last_seen_utc text,updated_at timestamptz);
                create table findings_refresh_state(pipeline_name text,last_status text);
                create table events_v2_core(id bigint primary key);
                insert into findings_refresh_state values('events_to_findings_v1','ok');
                """, ct);
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            ["ConnectionStrings:Sli"] = postgres.ConnectionString
        }).Build();
        var repository = new Sli.Server.Problems.ProblemRepository(new PostgresConnectionFactory(config), TimeProvider.System);
        var result = await repository.LegacyFindingsAsync("", 100, ct);
        Assert.Equal("ok", result.Text("status"));
        Assert.Equal("postgres", result.Text("backend"));
        Assert.Empty(result["items"]!.AsArray());
        Assert.Empty(result["limitations"]!.AsArray());
        Assert.Equal("disabled", result["refresh_status"]!.Text("status"));
    }

    [Fact] public async Task EmptyPostgresFindingsRefreshSucceedsWithoutPublishingFindings()
    {
        var db=new FindingsDatabase { Before=10,After=10,Events=new JsonArray(new JsonObject { ["id"]=11,["event_id"]=4740 }) };
        var result=await new LegacyFindings(db).RefreshAsync(TestContext.Current.CancellationToken);
        Assert.Equal("disabled",result.Text("status")); Assert.Equal("module_disabled",result.Text("reason"));
        Assert.Equal(10,db.After); Assert.Equal(0,db.Commits); Assert.Empty(db.Sql);
    }

    [Fact] public async Task LegacyFindingsAdvancesNonmatchingSliceWithoutPublishingUnqualifiedVerdicts()
    {
        var db=new FindingsDatabase { Before=10,After=10,Events=new JsonArray(new JsonObject { ["id"]=11,["event_id"]=4740 }) };
        var result=await new LegacyFindings(db).RefreshAsync(TestContext.Current.CancellationToken);
        Assert.Equal("disabled",result.Text("status")); Assert.Equal("module_disabled",result.Text("reason"));
        Assert.Equal(10,db.After); Assert.Equal(0,db.Commits); Assert.Empty(db.Sql);
    }
    [Theory] [InlineData(4740)] [InlineData(4724)] [InlineData(4723)] [InlineData(4728)] [InlineData(4732)] [InlineData(4756)] [InlineData(7045)]
    public async Task LegacyEventHintsRequireAdmittedPolicyAndNeverAdvanceWatermark(int eventId)
    {
        var db=new FindingsDatabase { Before=10,After=10,Events=new JsonArray(new JsonObject { ["id"]=11,["event_id"]=eventId }) };
        var result=await new LegacyFindings(db).RefreshAsync(TestContext.Current.CancellationToken);
        Assert.Equal("disabled",result.Text("status")); Assert.Equal("module_disabled",result.Text("reason"));
        Assert.Equal(10,db.After); Assert.Equal(0,db.Commits); Assert.Empty(db.Sql);
    }
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CommonWorkerReceivesActualLegacyPhaseAndClaimWithoutMonitorFailureChangingReport(bool monitorFails)
    {
        using var dir = new DirectoryScope(); var posts = new Posts(); var claim = Claim(); posts.Claims.Enqueue(claim);
        var updates = new List<JsonObject>();
        var result = await new LegacyPostCollection(posts, new Analysis(), Settings(dir.Path), NullLogger<LegacyPostCollection>.Instance)
            .RunOnceAsync("test-worker", 1, TestContext.Current.CancellationToken, (current, _) => {
                updates.Add((JsonObject)current.DeepClone());
                if (monitorFails) throw new InvalidOperationException("synthetic-private-monitor");
                return Task.CompletedTask;
            });
        Assert.Equal(new LegacyPostResult(1, 1, 0), result);
        Assert.Equal(new[] { "findings_running", "report_running" }, updates.Select(x => (string?)x["phase"]));
        Assert.All(updates, current => {
            Assert.Equal(claim.DurableId, (string?)current["durable_job_id"]);
            Assert.Equal(claim.Attempt, current["claim_attempt"]!.GetValue<int>());
            Assert.DoesNotContain("synthetic-private", current.ToJsonString());
        });
        Assert.Equal(1, posts.Published);
    }

    private sealed class Producer(bool fail=false) : ILegacyFindings
    {
        public int Calls;
        public Task<JsonObject> RefreshAsync(CancellationToken ct) { Calls++; if(fail)throw new InvalidOperationException("private-test-error"); return Task.FromResult(new JsonObject { ["status"]="ok",["created_findings"]=0 }); }
    }
    private sealed class Snapshot : ILegacyStorageSnapshot
    {
        public int Calls;
        public bool Cancelled;
        public Task RecordAsync(LegacyPostClaim claim,CancellationToken ct) { Calls++; Cancelled=ct.IsCancellationRequested; throw new IOException("private-test-error"); }
    }
    [Fact]
    public async Task EventIdFindingsAreDisabledByDefaultAndOwnedBySemanticScenarios()
    {
        using var dir = new DirectoryScope(); var posts = new Posts(); posts.Claims.Enqueue(Claim()); var producer = new Producer();
        var settings = Settings(dir.Path);
        Assert.Null(settings.Get("ADLOG_LEGACY_FINDINGS_ENABLED"));
        Assert.False(settings.Enabled("ADLOG_LEGACY_FINDINGS_ENABLED"));
        var result = await new LegacyPostCollection(posts, new Analysis(), settings, NullLogger<LegacyPostCollection>.Instance,
            producer: producer).RunOnceAsync("test-worker", 1, TestContext.Current.CancellationToken);
        Assert.Equal(new LegacyPostResult(1, 1, 0), result);
        Assert.Equal(0, producer.Calls);
        Assert.Equal("skipped", posts.Findings!["status"]!.GetValue<string>());
        Assert.Equal("legacy_event_id_verdict_producer_disabled", posts.Findings["reason"]!.GetValue<string>());
        Assert.Equal("semantic_scenarios", posts.Findings["verdict_owner"]!.GetValue<string>());
        foreach (string key in new[] { "created_findings", "updated_findings", "evidence_added" })
            Assert.Equal(0, posts.Findings[key]!.GetValue<int>());
    }
    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task EnabledFindingsProducerRunsAndSnapshotFailureCannotUndoPublishedReport(bool fail)
    {
        using var dir=new DirectoryScope();var posts=new Posts();posts.Claims.Enqueue(Claim());var producer=new Producer(fail);var snapshot=new Snapshot();
        var result=await new LegacyPostCollection(posts,new Analysis(),Settings(dir.Path,("ADLOG_LEGACY_FINDINGS_ENABLED","1")),NullLogger<LegacyPostCollection>.Instance,
            producer:producer,snapshots:snapshot).RunOnceAsync("test-worker",1,TestContext.Current.CancellationToken);
        Assert.Equal(new LegacyPostResult(1,1,0),result);Assert.Equal(1,producer.Calls);Assert.Equal(1,snapshot.Calls);
        Assert.Equal(fail ? 1 : 0,posts.FindingsWarnings);Assert.Equal(1,posts.Published);Assert.Equal(1,posts.Finishes);
        Assert.False(snapshot.Cancelled);
    }
    [Fact] public void StorageSnapshotUsesActualBoundedFilesystemSizes()
    {
        using var dir=new DirectoryScope();File.WriteAllBytes(System.IO.Path.Combine(dir.Path,"test-artifact.bin"),new byte[37]);
        var result=LegacyStorageSnapshot.Scan(dir.Path,TestContext.Current.CancellationToken);
        Assert.Equal(37,result.Number("bytes"));Assert.Equal(1,result.Number("files_seen"));Assert.False(result.Flag("truncated"));
    }
    [Fact] public void StorageSnapshotContinuesPastFormerEntryBudget()
    {
        using var dir = new DirectoryScope();
        for (int i = 0; i < 10001; i++) File.WriteAllBytes(System.IO.Path.Combine(dir.Path, "synthetic-" + i + ".bin"), [1]);
        var result = LegacyStorageSnapshot.Scan(dir.Path, TestContext.Current.CancellationToken);
        Assert.Equal(10001, result.Number("files_seen")); Assert.Equal(10001, result.Number("bytes"));
        Assert.False(result.Flag("truncated")); Assert.Null(result["reason"]);
    }
    [Theory] [InlineData("test")] [InlineData("shadow")]
    public void DevelopmentRiskAcceptsOnlyDevelopmentModes(string mode)=>SemanticProduction.RequireDevelopmentEvaluation(mode);
    [Theory] [InlineData("enabled")] [InlineData("draft")] [InlineData("")] [InlineData("ENABLED")]
    public void DevelopmentRiskRejectsPublicationModes(string mode)=>Assert.Throws<InvalidOperationException>(()=>SemanticProduction.RequireDevelopmentEvaluation(mode));
}
