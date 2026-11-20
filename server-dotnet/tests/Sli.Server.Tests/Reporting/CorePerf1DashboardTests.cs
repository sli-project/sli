using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Sli.Server.Compatibility;
using Sli.Server.Legacy;
using Sli.Server.Operations;
using Sli.Server.Workspace;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Agents;
using Npgsql;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed class CorePerf1DashboardTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static JsonArray Array(string json) => JsonNode.Parse(json)!.AsArray();
    static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);

    sealed class Source : ILegacyRows, IOperationsQueries, ILegacyHttpReader
    {
        public readonly ConcurrentQueue<(string Sql, object[] Parameters, int Timeout)> Reads = new();
        public readonly ConcurrentQueue<string> Operations = new();
        public readonly TaskCompletionSource SummariesStarted = Signal(), AiStarted = Signal(), Release = Signal();
        public bool Block, FailEntities;
        int summaries;
        public long EventEstimate = 10, CatalogCount = 10;
        public JsonArray States = [], History = [];
        public Func<string, object[], JsonArray>? Script;
        public async Task<JsonArray> QueryAsync(string sql, IReadOnlyList<object> parameters, int timeoutMs, CancellationToken ct)
        {
            Reads.Enqueue((sql, parameters.ToArray(), timeoutMs));
            if (sql == WorkspaceOverview.SummarySql)
            {
                if (Interlocked.Increment(ref summaries) == 2) SummariesStarted.TrySetResult();
                if (Block) await Release.Task.WaitAsync(ct);
                return new(new JsonObject { ["events_total"] = EventEstimate, ["entities_total"] = 5 });
            }
            if (FailEntities && sql.Contains("as entity_type")) throw new InvalidOperationException("fixture entity failure");
            if (Script is not null) return Script(sql, parameters.ToArray());
            if (sql.Contains("group by channel order by count")) return new(new JsonObject { ["channel"] = "Security", ["count"] = CatalogCount });
            if (sql==DashboardSnapshotReader.ShortLinkCountSql) return Array("""[{"count":8}]""");
            return [];
        }
        public Task<JsonArray> ReadAsync(string sql, CancellationToken ct, params (string Name, object? Value)[] parameters)
        {
            Operations.Enqueue(sql);
            return Task.FromResult(sql == OperationsSql.CollectorState ? States.DeepClone().AsArray()
                : sql == OperationsSql.CollectorHistory ? History.DeepClone().AsArray() : new JsonArray());
        }
        public async Task<JsonObject> ReadAsync(string path, LegacyQuery query, CancellationToken ct)
        {
            AiStarted.TrySetResult();
            if (Block) await Release.Task.WaitAsync(ct);
            return new() { ["items"] = new JsonArray() };
        }
        public Task<JsonArray> HistoryAsync(string sql, IReadOnlyDictionary<string, string> parameters, CancellationToken ct) => throw new InvalidOperationException("unexpected history read");
        public Task<Dictionary<long, JsonObject>> HistoryEventsAsync(long[] ids, CancellationToken ct) => throw new InvalidOperationException("unexpected history read");
    }
    sealed class Files(IConfiguration config) : OperationsFiles(config)
    {
        public readonly TaskCompletionSource StorageStarted = Signal();
        public bool FailStorage;
        public override JsonObject RuntimeStorage(bool force, DateTimeOffset now)
        {
            Assert.False(force); StorageStarted.TrySetResult();
            if (FailStorage) throw new InvalidOperationException("fixture storage failure");
            return new() { ["status"] = "warming" };
        }
        public override JsonObject? Json(string relative, int maxBytes = 2097152) => null;
        public override JsonObject? PluginHeartbeat(string component) => null;
        public override JsonObject? NativeHeartbeat(string name) => null;
        public override JsonArray LogTail(string name, int lines) => [];
    }
    sealed class Fixture : IAsyncDisposable
    {
        public Source Source { get; } = new();
        readonly ServiceProvider provider;
        public DashboardSnapshotReader Reader { get; }
        public OperationsService Operations { get; }
        public Files Files { get; }
        public DashboardWarmupService Warmup => provider.GetServices<IHostedService>().OfType<DashboardWarmupService>().Single();
        public DashboardSnapshotCache Cache => provider.GetRequiredService<DashboardSnapshotCache>();
        public Fixture()
        {
            var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
                ["Sli:DataDirectory"] = Path.Combine(Path.GetTempPath(), "sli-perf1-" + Guid.NewGuid().ToString("N")),
                ["Sli:Operations:ADLOG_DC_CONNECT_MAP"] = "", ["Sli:Operations:ADLOG_DOMAIN_CONTROLLER_CONNECT_MAP"] = ""
            }).Build();
            var services = new ServiceCollection();
            services.AddLogging(); services.AddSingleton<IConfiguration>(config);
            services.AddSingleton<ILegacyRows>(Source); services.AddSingleton<IOperationsQueries>(Source); services.AddSingleton<ILegacyHttpReader>(Source);
            Files = new Files(config);
            services.AddSingleton<OperationsFiles>(Files); services.AddSingleton<OperationsCatalog>(); services.AddSingleton<OperationsJobs>();
            services.AddSingleton(TimeProvider.System); services.AddScoped<OperationsService>(); services.AddSingleton<LegacySettings>(); services.AddSingleton<LegacyJobStore>();
            services.AddWorkspaceCompatibility(); provider = services.BuildServiceProvider();
            Reader = provider.GetRequiredService<DashboardSnapshotReader>(); Operations = provider.GetRequiredService<OperationsService>();
        }
        public async ValueTask DisposeAsync()
        {
            Source.Release.TrySetResult();
            if (Cache.Refresh is {} refresh) { try { await refresh; } catch { } }
            await provider.DisposeAsync();
        }
    }

    [Fact]
    public async Task ComponentsStartInParallelBeforeAnyBlockedComponentCompletes()
    {
        await using var fixture = new Fixture(); fixture.Source.Block = true;
        var build = fixture.Reader.ReadAsync(true, Ct);
        try
        {
            // Both beta summaries start together; the disabled AI module is never read.
            await fixture.Source.SummariesStarted.Task.WaitAsync(Ct);
            Assert.False(fixture.Source.AiStarted.Task.IsCompleted);
            Assert.False(build.IsCompleted);
        }
        finally { fixture.Source.Release.TrySetResult(); }
        var result = await build;
        Assert.Equal("ok", result["status"]!.ToString());
        Assert.Equal("parallel_bounded_snapshot", result["diagnostics"]!["request_model"]!.ToString());
    }

    [Fact]
    public async Task FailedEntityComponentReturnsPartialSnapshotAndPreservesEvents()
    {
        await using var fixture = new Fixture(); fixture.Source.FailEntities = true;
        var result = await fixture.Reader.ReadAsync(true, Ct);
        Assert.Equal("partial", result["status"]!.ToString());
        Assert.Equal("entity_summary", Assert.Single(result["diagnostics"]!["failures"]!.AsArray())!.ToString());
        Assert.Equal("failed", result["diagnostics"]!["components"]!["entity_summary"]!["status"]!.ToString());
        Assert.Equal("unavailable", result["entity_summary"]!["status"]!.ToString());
        Assert.Equal(10, result["events_summary"]!["total_events"]!.GetValue<long>());
    }

    [Fact]
    public async Task CancelledWaiterDoesNotDuplicateRunningComponents()
    {
        await using var fixture = new Fixture(); fixture.Source.Block = true;
        using var cancelled = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        var first = fixture.Reader.ReadAsync(true, cancelled.Token);
        await fixture.Source.SummariesStarted.Task.WaitAsync(Ct);
        cancelled.Cancel(); await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first);
        var flight = fixture.Cache.Refresh;
        var second = fixture.Reader.ReadAsync(true, Ct);
        Assert.Same(flight, fixture.Cache.Refresh);
        Assert.Equal(2, fixture.Source.Reads.Count(r => r.Sql == WorkspaceOverview.SummarySql));
        Assert.False(second.IsCompleted);
        fixture.Source.Release.TrySetResult();
        Assert.Equal("ok", (await second)["status"]!.ToString());
    }

    [Theory]
    [InlineData("ok", "stale")]
    [InlineData("partial", "partial")]
    public async Task ExpiredCacheIsServedWhileOneRefreshStarts(string cachedStatus, string expected)
    {
        await using var fixture = new Fixture(); fixture.Source.Block = true;
        lock (fixture.Cache.Sync)
        {
            fixture.Cache.Payload = new() { ["status"] = cachedStatus, ["diagnostics"] = new JsonObject { ["total_duration_ms"] = 12 }, ["events_summary"] = new JsonObject { ["total_events"] = 9 } };
            fixture.Cache.Created = Stopwatch.GetTimestamp() - 30 * Stopwatch.Frequency;
        }
        var result = await fixture.Reader.ReadAsync(false, Ct);
        var flight = fixture.Cache.Refresh;
        await fixture.Reader.ReadAsync(false, Ct);
        Assert.Same(flight, fixture.Cache.Refresh);
        Assert.Equal(expected, result["status"]!.ToString());
        Assert.Equal(9, result["events_summary"]!["total_events"]!.GetValue<int>());
        foreach (string key in new[] { "cache_hit", "stale", "refreshing" }) Assert.True(result["diagnostics"]![key]!.GetValue<bool>());
        result["events_summary"]!["total_events"] = -1;
        Assert.Equal(9, fixture.Cache.Payload!["events_summary"]!["total_events"]!.GetValue<int>());
        fixture.Source.Release.TrySetResult(); await flight!.WaitAsync(Ct);
        var fresh = await fixture.Reader.ReadAsync(false, Ct);
        Assert.Equal("ok", fresh["status"]!.ToString()); Assert.False(fresh["diagnostics"]!["stale"]!.GetValue<bool>());
    }

    [Fact]
    public void EmptyPreloadedRoleDataProducesThreeViewsWithoutReaders()
    {
        var result = DashboardSnapshotReader.RoleViews(new JsonObject(), new JsonObject(), new JsonObject(), new JsonObject(), new JsonObject(), new JsonObject(), new JsonArray());
        Assert.Equal(3, result["views"]!.AsArray().Count);
        Assert.Equal(0, result["summary"]!["total_events"]!.GetValue<long>());
    }

    [Fact]
    public async Task FindingsUsesExactlyTwoQueriesWithoutLoadingRelations()
    {
        await using var fixture = new Fixture();
        fixture.Source.Script = (sql, _) => sql.Contains("group by severity") ? Array("""[{"severity":"high","status":"new","count":1}]""") : Array("""[{"id":1,"severity":"high","status":"new"}]""");
        var result = await fixture.Reader.Findings(Ct);
        Assert.False(result["details_included"]!.GetValue<bool>());
        Assert.Single(result["items"]!.AsArray()); Assert.Single(result["summary"]!.AsArray());
        Assert.Equal(2, fixture.Source.Reads.Count);
        Assert.All(fixture.Source.Reads, read => {
            Assert.Contains("findings_active", read.Sql);
            foreach (string relation in new[] { "finding_evidence", "finding_entities", "finding_status_history" }) Assert.DoesNotContain(relation, read.Sql);
        });
    }

    [Theory]
    [InlineData("updated_at")]
    [InlineData("last_successful_collection_utc")]
    [InlineData("last_collection_start_utc")]
    public async Task CollectorUsesOneStateAndOneHistoryQueryAndKeepsLatestCaseIdentity(string newestField)
    {
        await using var fixture = new Fixture();
        var stale = JsonNode.Parse("""{"server_hostname":"dc1","channel":"Security","last_successful_collection_utc":"2026-08-14T23:43:32+00:00","updated_at":"2026-08-14T23:43:33+00:00"}""")!.AsObject();
        var current = stale.DeepClone().AsObject(); current["server_hostname"] = "DC1"; current[newestField] = "2026-08-25T23:38:47+00:00";
        fixture.Source.States = new(stale, current);
        fixture.Source.History = Array("""[{"server":"DC1","channel":"Security","inserted":10,"skipped":1,"last_status":"completed"}]""");
        var result = await fixture.Operations.CollectorAsync(Ct);
        var item = Assert.Single(result["items"]!.AsArray())!;
        Assert.Equal("DC1", item["server"]!.ToString()); Assert.Equal("completed", item["last_status"]!.ToString());
        Assert.Equal(10, item["inserted_24h"]!.GetValue<long>()); Assert.Equal(1, item["skipped_24h"]!.GetValue<long>());
        Assert.Single(fixture.Source.Operations, sql => sql == OperationsSql.CollectorState);
        Assert.Single(fixture.Source.Operations, sql => sql == OperationsSql.CollectorHistory);
        Assert.Contains("collector_channel_runs", OperationsSql.CollectorState);
        Assert.DoesNotContain("from events", OperationsSql.CollectorState.ToLowerInvariant());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task StartupWarmsDashboardAndStorageWithoutWaitingForQueries(bool failStorage)
    {
        await using var fixture = new Fixture(); fixture.Source.Block = true; fixture.Files.FailStorage = failStorage;
        var warmup = fixture.Warmup;
        await warmup.StartAsync(Ct);
        try
        {
            await Task.WhenAll(fixture.Files.StorageStarted.Task, fixture.Source.SummariesStarted.Task).WaitAsync(Ct);
            Assert.False(warmup.ExecuteTask!.IsCompleted); Assert.Null(fixture.Cache.Payload);
        }
        finally { fixture.Source.Release.TrySetResult(); }
        await warmup.ExecuteTask!.WaitAsync(Ct);
        Assert.Equal("ok", fixture.Cache.Payload!["status"]!.ToString());
        await warmup.StopAsync(Ct);
    }

    sealed class Database(string connectionString) : IPostgresConnectionFactory
    {
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
        {
            var connection = new NpgsqlConnection(connectionString); await connection.OpenAsync(ct); return connection;
        }
    }
    [Fact]
    public async Task DashboardQueryPolicyDoesNotInstallTimeoutsAndOtherCallersKeepTheirPolicy()
    {
        await using var pg = new PostCollectionPostgres(); await pg.StartAsync(Ct);
        using var rows = new PostgresLegacyRows(new Database(pg.ConnectionString));
        const string sql = "select current_setting('statement_timeout') as statement_timeout,current_setting('lock_timeout') as lock_timeout,@p0::integer as value";
        var dashboard = Assert.Single(await rows.QueryAsync(sql, [42], 0, Ct))!;
        Assert.Equal("0", dashboard["statement_timeout"]!.ToString()); Assert.Equal("0", dashboard["lock_timeout"]!.ToString());
        Assert.Equal(42, dashboard["value"]!.GetValue<int>());
        var legacy = Assert.Single(await rows.QueryAsync(sql, [43], 8000, Ct))!;
        Assert.Equal("8s", legacy["statement_timeout"]!.ToString()); Assert.Equal("1s", legacy["lock_timeout"]!.ToString());
        Assert.Equal(43, legacy["value"]!.GetValue<int>());
    }
}
