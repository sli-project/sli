using System.Collections.Concurrent;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Legacy;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Legacy;

// Behavioral vectors from tests/sources/test_runtime_orchestrator1.py.
public sealed class RuntimeOrchestratorParityTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static LegacySettings Settings(string directory) => new(new ConfigurationBuilder().AddInMemoryCollection(
        new Dictionary<string, string?> {
            ["Sli:DataDirectory"] = directory, ["Sli:Legacy:SLI_LEGACY_COLLECTION_DISABLED"] = "0",
            ["Sli:Legacy:ADLOG_ACQUISITION_DISABLED"] = "0", ["Sli:Legacy:ADLOG_EXTERNAL_POST_COLLECTION_WORKER"] = "1",
            ["Sli:Legacy:ADLOG_ENABLE_INPROCESS_POST_COLLECTION"] = "1", ["Sli:Legacy:ADLOG_SCHEDULER_SKIP_REPORT"] = "0"
        }).Build());

    private sealed class Connections(string dsn) : IPostgresConnectionFactory
    {
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct) { var db = new NpgsqlConnection(dsn); await db.OpenAsync(ct); return db; }
    }
    private sealed class EnvironmentStub : ILegacyEnvironment
    {
        public Task<string[]> TargetsAsync(CancellationToken ct) => Task.FromResult(new[] { "DC1" });
        public Task<JsonObject> DiskGuardAsync(CancellationToken ct) => Task.FromResult(new JsonObject { ["collection_allowed"] = true });
        public Task<string?> CollectionBlockAsync(CancellationToken ct) => Task.FromResult<string?>(null);
    }
    private sealed class Acquisition : ILegacyAcquisition
    {
        public Task<LegacyCollectionBatch> CollectAsync(LegacyJobInput input, CancellationToken ct) => throw new InvalidOperationException("real acquisition is outside this cycle vector");
    }
    private sealed class Analysis : ILegacyAnalysis
    {
        public int Calls;
        public Func<CancellationToken, Task>? Running;
        public long Source;
        public string[] Servers = [];
        public async Task<LegacyReport> RenderAsync(long id, string[] servers, CancellationToken ct) {
            Calls++; Source = id; Servers = servers;
            if (Running is not null) await Running(ct);
            return new("/reports/test.html", [new("test.html", "ok")]);
        }
    }
    private sealed class Posts : ILegacyPostStore
    {
        public readonly Queue<LegacyPostClaim> Claims = new();
        public readonly ConcurrentQueue<(LegacyPostClaim Claim, string Phase)> Pulses = new();
        public readonly List<(string Id, int Source, string[] Servers)> Queued = [];
        public readonly List<(string Worker, int Limit)> Requests = [];
        public Func<string, Exception?>? HeartbeatFailure;
        public int Published, Finished;
        public Task QueueAsync(string durableId, int sourceId, string[] servers, CancellationToken ct) { Queued.Add((durableId, sourceId, servers)); return Task.CompletedTask; }
        public Task RecoverAsync(CancellationToken ct) => Task.CompletedTask;
        public Task<IReadOnlyList<LegacyPostClaim>> ClaimAsync(string worker, int limit, CancellationToken ct) {
            Requests.Add((worker, limit)); return Task.FromResult<IReadOnlyList<LegacyPostClaim>>(Claims.Count == 0 ? [] : [Claims.Dequeue()]);
        }
        public Task HeartbeatAsync(LegacyPostClaim claim, string phase, CancellationToken ct) {
            Pulses.Enqueue((claim, phase)); if (HeartbeatFailure?.Invoke(phase) is {} error) throw error; return Task.CompletedTask;
        }
        public Task FindingsAsync(LegacyPostClaim claim, JsonObject result, string? errorId, CancellationToken ct) => Task.CompletedTask;
        public Task FinishAsync(LegacyPostClaim claim, string? path, string? errorId, CancellationToken ct) { if (errorId is null) Finished++; return Task.CompletedTask; }
        public async Task FenceAsync(LegacyPostClaim claim, Func<Task> publish, CancellationToken ct) { await publish(); Published++; }
    }
    private sealed class RecordingLogger : ILogger<LegacyPostCollection>
    {
        public readonly ConcurrentQueue<string> Messages = new();
        public bool IsEnabled(LogLevel level) => true;
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? error, Func<TState, Exception?, string> formatter) => Messages.Enqueue(formatter(state, error));
    }

    [Theory]
    [InlineData("completed", "queued")]
    [InlineData("partial", "queued")]
    [InlineData("failed", "not_queued")]
    public async Task OneCollectionCyclePersistsHistoryAndOnlyQueuesEligiblePostWork(string status, string queued)
    {
        using var services=new ServiceCollection().BuildServiceProvider();
        var error=await Assert.ThrowsAsync<InvalidOperationException>(()=>LegacyWorkerCommand.RunCollectionCycleAsync(services,"fixture",1,100,Ct, (_,_)=>throw new Exception("unexpected execution:"+status+queued)));
        Assert.Equal("module_disabled",error.Message);
    }

    [Fact]
    public async Task ExternalModeDoesNotStartTheInProcessPostExecutor()
    {
        // No scope factory: entering the executor would fail this test.
        using var service = new LegacyPostCollectionHostedService(null!, Settings(Path.GetTempPath()), NullLogger<LegacyPostCollectionHostedService>.Instance);
        await service.StartAsync(Ct); await service.ExecuteTask!.WaitAsync(Ct); await service.StopAsync(Ct);
        Assert.True(service.ExecuteTask.IsCompletedSuccessfully);
    }

    [Fact]
    public async Task IndependentWorkerPassesDurableIdentityServersWorkerAndAttemptToExecution()
    {
        string directory = Path.Combine(Path.GetTempPath(), "sli-runtime-parity-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try {
            var posts = new Posts(); var claim = new LegacyPostClaim("durable-1", 4101, ["DC1"], "worker-a", 1); posts.Claims.Enqueue(claim);
            var analysis = new Analysis();
            var result = await new LegacyPostCollection(posts, analysis, Settings(directory), NullLogger<LegacyPostCollection>.Instance).RunOnceAsync("worker-a", 1, Ct);
            Assert.Equal(new LegacyPostResult(1, 1, 0), result); Assert.Equal(("worker-a", 1), Assert.Single(posts.Requests));
            Assert.Equal(4101, analysis.Source); Assert.Equal(new[] { "DC1" }, analysis.Servers);
            Assert.All(posts.Pulses, pulse => Assert.Equal(claim, pulse.Claim)); Assert.Equal(1, posts.Published); Assert.Equal(1, posts.Finished);
            Assert.Equal("ok", await File.ReadAllTextAsync(Path.Combine(directory, "reports", "test.html"), Ct));
        } finally { Directory.Delete(directory, true); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ReportRenewsDurableAndWorkerHeartbeatsAndSurvivesTransientHeartbeatFailure(bool fail)
    {
        await using var pg = new PostCollectionPostgres(); await pg.StartAsync(Ct);
        var connections = new Connections(pg.ConnectionString); var posts = new Posts(); var logger = new RecordingLogger();
        var claim = new LegacyPostClaim("durable-7", 7, ["DC1"], "post-worker", 1); posts.Claims.Enqueue(claim);
        using var tick = new SemaphoreSlim(0); var waiting = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int delays = 0; var waitingForNext = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var analysis = new Analysis();
        posts.HeartbeatFailure = phase => fail && phase == "report_running" ? new InvalidOperationException("lease unavailable private diagnostic") : null;
        analysis.Running = async ct => {
            await waiting.Task.WaitAsync(ct);
            await using var db = await connections.OpenAsync(ct);
            await using var before = new NpgsqlCommand("select heartbeat_at from runtime_worker_heartbeats where worker_name='post_collection'", db);
            var first = (DateTime)(await before.ExecuteScalarAsync(ct))!;
            tick.Release();
            // The next delay starts only after both heartbeat writes have finished.
            await waitingForNext.Task.WaitAsync(ct);
            await using var after = new NpgsqlCommand("select heartbeat_at,worker_id,phase,details_json from runtime_worker_heartbeats where worker_name='post_collection'", db);
            await using var reader = await after.ExecuteReaderAsync(ct); Assert.True(await reader.ReadAsync(ct));
            Assert.True(reader.GetDateTime(0) > first); Assert.Equal("post-worker", reader.GetString(1)); Assert.Equal("report_running", reader.GetString(2));
            Assert.Equal("durable-7", JsonNode.Parse(reader.GetString(3))!["durable_job_id"]!.GetValue<string>());
        };
        var worker = new LegacyPostCollection(posts, analysis, Settings(pg.Root), logger, heartbeat: new LegacyHeartbeat(connections)) {
            Delay = async (_, ct) => { if (Interlocked.Increment(ref delays) == 1) waiting.SetResult(); else waitingForNext.TrySetResult(); await tick.WaitAsync(ct); }
        };
        var result = await worker.RunOnceAsync("post-worker", 1, Ct);
        Assert.Equal(new LegacyPostResult(1, 1, 0), result);
        Assert.True(posts.Pulses.Count(x => x.Phase == "report_running") >= 2);
        Assert.Equal("ok", await File.ReadAllTextAsync(Path.Combine(pg.Root, "reports", "test.html"), Ct));
        Assert.Equal(fail, logger.Messages.Contains("post_collection_heartbeat_failed"));
        Assert.DoesNotContain(logger.Messages, message => message.Contains("private", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ExplicitLeaseLossDuringReportStillStopsBeforePublication()
    {
        string directory = Path.Combine(Path.GetTempPath(), "sli-runtime-parity-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try {
            var posts = new Posts(); posts.Claims.Enqueue(new("durable-8", 8, ["DC1"], "post-worker", 1));
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var analysis = new Analysis { Running = async ct => { entered.SetResult(); await Task.Delay(Timeout.InfiniteTimeSpan, ct); } };
            int pulses = 0;
            posts.HeartbeatFailure = phase => phase == "report_running" && Interlocked.Increment(ref pulses) > 1 ? new LegacyLeaseLost() : null;
            var worker = new LegacyPostCollection(posts, analysis, Settings(directory), NullLogger<LegacyPostCollection>.Instance) {
                Delay = async (_, ct) => { await entered.Task.WaitAsync(ct); await Task.Yield(); }
            };
            var result = await worker.RunOnceAsync("post-worker", 1, Ct);
            Assert.Equal(new LegacyPostResult(1, 0, 1), result); Assert.Equal(0, posts.Published); Assert.Equal(0, posts.Finished);
            Assert.Empty(Directory.GetFiles(directory, "*", SearchOption.AllDirectories));
        } finally { Directory.Delete(directory, true); }
    }

    [Theory]
    [InlineData("collection-worker")]
    [InlineData("legacy-post-collection-worker")]
    public async Task WorkerHelpExitsWithoutStartingCollectionOrWeb(string role) =>
        Assert.Equal(0, await LegacyWorkerCommand.RunAsync(role, ["--help"]));

    [Fact]
    public void HistoryDiagnosticsKeepFirstSeenOrderAndRemoveOnlyExactDuplicates()
    {
        Assert.Equal(new[] { "DC1: DNS denied", "DC2: DNS denied" }, LegacyCollectionHistory.UniqueTexts(["DC1: DNS denied", "DC2: DNS denied", "DC1: DNS denied"]));
        Assert.Empty(LegacyCollectionHistory.UniqueTexts(null));
        Assert.Equal(new[] { " ", "Error", "error" }, LegacyCollectionHistory.UniqueTexts(["", " ", "Error", "error", "Error"]));
    }
}
