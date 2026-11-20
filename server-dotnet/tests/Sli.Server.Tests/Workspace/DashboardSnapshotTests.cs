using System.Diagnostics;
using System.Net;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Compatibility;
using Sli.Server.Legacy;
using Sli.Server.Operations;
using Sli.Server.Workspace;
using Xunit;

namespace Sli.Server.Tests.Workspace;

public sealed class DashboardSnapshotTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static JsonObject Reference() {
        using var stream = typeof(DashboardSnapshotTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Workspace.dashboard-reference.json")!;
        return JsonNode.Parse(stream)!.AsObject();
    }
    static void Equal(JsonNode? expected, JsonNode? actual) => Assert.True(JsonNode.DeepEquals(expected, actual), $"Expected: {expected}\nActual: {actual}");
    static JsonNode Normalize(JsonNode value) {
        var clone = value.DeepClone();
        void Walk(JsonNode? node) {
            if (node is JsonObject obj) foreach (var key in obj.Select(p => p.Key).ToArray()) {
                if (key == "generated_at_utc") obj[key] = "<generated>";
                else if (key == "components_ms" && obj[key] is JsonObject timings) foreach (var name in timings.Select(p => p.Key).ToArray()) timings[name] = 0;
                else if (key.EndsWith("_ms") && obj[key] is not JsonObject) obj[key] = 0;
                else Walk(obj[key]);
            }
            else if (node is JsonArray array) foreach (var item in array) Walk(item);
        }
        Walk(clone); return clone;
    }
    sealed class Rows : ILegacyRows, IOperationsQueries {
        public int Calls;
        public bool FailEntities;
        public readonly TaskCompletionSource Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource? Release;
        public async Task<JsonArray> QueryAsync(string sql, IReadOnlyList<object> parameters, int timeoutMs, CancellationToken ct) {
            Interlocked.Increment(ref Calls); Started.TrySetResult();
            if (Release is {} release) await release.Task.WaitAsync(ct);
            if (FailEntities && sql.Contains("entities_v2_active")) throw new InvalidOperationException("fixture failure");
            if (sql.Contains("as events_total")) return JsonNode.Parse("""[{"events_total":9,"entities_total":3}]""")!.AsArray();
            if (sql.Contains("group by channel order by count")) return JsonNode.Parse("""[{"channel":"Security","count":9}]""")!.AsArray();
            if (sql==DashboardSnapshotReader.ShortLinkCountSql || sql.Contains("as count from pg_class") || sql.Contains("as estimated_rows")) return JsonNode.Parse("""[{"count":6,"estimated_rows":6}]""")!.AsArray();
            return [];
        }
        public Task<JsonArray> ReadAsync(string sql, CancellationToken ct, params (string Name, object? Value)[] parameters) => Task.FromResult(new JsonArray());
        public Task<JsonArray> HistoryAsync(string sql, IReadOnlyDictionary<string, string> parameters, CancellationToken ct) => throw new InvalidOperationException();
        public Task<Dictionary<long, JsonObject>> HistoryEventsAsync(long[] ids, CancellationToken ct) => throw new InvalidOperationException();
    }
    sealed class Files(IConfiguration config) : OperationsFiles(config) {
        public override JsonObject? Json(string relative, int maxBytes = 2097152) => null;
        public override JsonObject? PluginHeartbeat(string component) => null;
        public override JsonObject? NativeHeartbeat(string name) => null;
        public override JsonArray LogTail(string name, int lines) => [];
    }
    sealed class Legacy : ILegacyHttpReader {
        public Task<JsonObject> ReadAsync(string path, LegacyQuery query, CancellationToken ct) => throw new InvalidOperationException("retired_reader_must_not_run");
    }
    static IConfiguration Config() => new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
        ["Sli:DataDirectory"] = Path.Combine(Path.GetTempPath(), "sli-dashboard-fixture-" + Guid.NewGuid().ToString("N")),
        ["Sli:Legacy:ADLOG_DASHBOARD_CACHE_TTL_SECONDS"] = "17", ["Sli:AuthRequired"] = "1"
    }).Build();
    static void Services(IServiceCollection services, Rows rows, IConfiguration config) {
        services.AddLogging(); services.AddSingleton(config); services.AddSingleton<ILegacyRows>(rows); services.AddSingleton<IOperationsQueries>(rows);
        services.AddSingleton<OperationsFiles>(new Files(config)); services.AddSingleton<OperationsCatalog>(); services.AddSingleton<OperationsJobs>();
        services.AddSingleton(TimeProvider.System); services.AddScoped<OperationsService>(); services.AddSingleton<LegacySettings>(); services.AddSingleton<LegacyJobStore>();
        services.AddSingleton<ILegacyHttpReader, Legacy>(); services.AddWorkspaceCompatibility();
        foreach (var service in services.Where(s => s.ServiceType == typeof(IHostedService) && s.ImplementationType == typeof(DashboardWarmupService)).ToArray()) services.Remove(service);
        services.AddScoped<IWorkspaceCompatibilityReader>(s => new WorkspaceCompatibilityReader(null!, config, null!, s.GetRequiredService<DashboardSnapshotReader>(), null!));
    }
    [Fact]
    public async Task ForcedBuildPreservesSummaryCountsTtlAndDiagnostics() {
        var rows = new Rows(); var services = new ServiceCollection(); Services(services, rows, Config());
        await using var provider = services.BuildServiceProvider(); await using var scope = provider.CreateAsyncScope();
        var actual = await scope.ServiceProvider.GetRequiredService<DashboardSnapshotReader>().ReadAsync(true, Ct);
        var expected = Reference()["cases"]![0]!["payload"]!;
        Assert.Equal(9, actual["events_summary"]!["total_events"]!.GetValue<long>());
        Assert.Equal(9, Assert.Single(actual["events_summary"]!["by_channel"]!.AsArray())!["count"]!.GetValue<long>());
        Assert.False(actual["events_summary"]!["estimated"]!.GetValue<bool>());
        Equal(expected["entity_summary"], actual["entity_summary"]);
        Equal(expected["diagnostics"]!["cache_ttl_seconds"], actual["diagnostics"]!["cache_ttl_seconds"]);
        Assert.Equal(expected["diagnostics"]!["components"]!.AsObject().Select(p => p.Key).Order(), actual["diagnostics"]!["components"]!.AsObject().Select(p => p.Key).Order());
    }
    [Fact]
    public void RoleViewsMatchPythonIncludingMalformedAndNegativeLag() {
        var input = Reference()["cases"]![0]!["components"]!;
        var system = new JsonObject { ["status"] = "warn", ["retention"] = new JsonObject { ["candidates"] = 0 } };
        var actual = DashboardSnapshotReader.RoleViews(input["events_summary"]!, input["entity_summary"]!, input["collector_health"]!, system, input["findings"]!, input["ai_runs"]!, input["sources"]!);
        actual["generated_at_utc"] = "<generated>";
        Equal(Reference()["cases"]![0]!["payload"]!["role_views"], actual);
    }
    [Fact]
    public async Task CompleteEmptyAndPartialSnapshotsMatchPythonFixture() {
        var services = new ServiceCollection(); Services(services, new Rows(), Config());
        await using var provider = services.BuildServiceProvider(); await using var scope = provider.CreateAsyncScope();
        var reader = scope.ServiceProvider.GetRequiredService<DashboardSnapshotReader>();
        foreach (var item in Reference()["cases"]!.AsArray()) {
            var inputs = item!["components"]!.AsObject().ToDictionary(p => p.Key, p => p.Value!.DeepClone());
            if (item["failure"] is not null) inputs["entity_summary"] = JsonNode.Parse("""{"total_entities":0,"total_event_entity_links":0,"by_type":[],"by_role":[],"status":"unavailable"}""")!;
            var diagnostics = item["payload"]!["diagnostics"]!["components"]!.DeepClone().AsObject(); diagnostics.Remove("role_views_compose");
            var actual = reader.Compose(inputs, item["runtime"]!.DeepClone(), diagnostics, 0);
            Equal(item["payload"], Normalize(actual));
            Equal(item["warming"], Normalize(reader.WarmingResponse(item["runtime"]!.DeepClone())));
        }
    }
    sealed class Authentication(bool loggedIn, string role) : IPrincipalAuthenticator {
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext c, CancellationToken ct) => ValueTask.FromResult(loggedIn ? AuthenticationResult.Success(new("session", 1, role)) : AuthenticationResult.Denied(401, "authentication_required"));
    }
    sealed class Facts(bool allowed) : IAccessFactsRepository {
        public Task<AccessFacts> LoadAsync(Principal principal, CancellationToken ct) => Task.FromResult(new AccessFacts(false, principal.Role, [], [],
            allowed ? [System.Text.Json.JsonSerializer.SerializeToElement(new { capability_key = "workspace.view", effect = "allow", scope_json = new { kind = "all" } })] : [], [], [], [], []));
    }
    static Task<IHost> Host(Rows rows, bool allowed = true, bool loggedIn = true, string role = "operator", bool runtimeFailure = false) {
        var config = new ConfigurationBuilder().AddConfiguration(Config()).AddInMemoryCollection(new Dictionary<string, string?> {
            ["Sli:Operations:ADLOG_DC_CONNECT_MAP"] = runtimeFailure ? "fixture" : ""
        }).Build();
        return new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(s => {
            Services(s, rows, config); s.AddRouting(); s.AddSingleton(new AuthRequestPolicy(config)); s.AddSingleton(new TransportGate(config));
            s.AddSingleton<IPrincipalAuthenticator>(new Authentication(loggedIn, role)); s.AddSingleton<IAccessFactsRepository>(new Facts(allowed));
        }).Configure(app => { app.UseRouting(); app.UseReadRoleRequestGate(); app.UseEndpoints(e => e.MapWorkspaceCompatibility()); })).StartAsync(Ct);
    }
    [Fact]
    public async Task ForceParsingControlsRefreshAndFreshCachePreservesDataThroughHttp() {
        using var host = await Host(new Rows()); using var client = host.GetTestClient();
        var cache = host.Services.GetRequiredService<DashboardSnapshotCache>();
        foreach (var item in Reference()["forces"]!.AsArray()) {
            lock (cache.Sync) { cache.Payload = Reference()["cases"]![0]!["payload"]!.DeepClone().AsObject(); cache.Created = Stopwatch.GetTimestamp(); }
            using var response = await client.GetAsync("/api/dashboard/snapshot?" + item!["query"]!.ToString() + "&ignored=bad", Ct);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("application/json", response.Content.Headers.ContentType!.MediaType);
            var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(Ct))!;
            Assert.Equal(!item["force"]!.GetValue<bool>(), body["diagnostics"]!["cache_hit"]!.GetValue<bool>());
            if (!item["force"]!.GetValue<bool>())
                foreach (string field in new[] { "events_summary", "entity_summary", "sources", "role_views" })
                    Equal(Reference()["cases"]![0]!["fresh"]![field], Normalize(body)[field]);
        }
    }
    [Theory]
    [InlineData(false, true, "operator", 403)]
    [InlineData(true, false, "operator", 401)]
    [InlineData(true, true, "viewer", 200)]
    public async Task HttpRightsAreCheckedBeforeAnySnapshotRead(bool allowed, bool loggedIn, string role, int status) {
        var rows = new Rows(); using var host = await Host(rows, allowed, loggedIn, role); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/dashboard/snapshot?force=yes", Ct);
        Assert.Equal(status, (int)response.StatusCode);
        if (status != 200) {
            Assert.Equal(0, rows.Calls);
            var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(Ct))!;
            Assert.Equal(status == 401 ? "authentication_required" : "insufficient_capability", body["error"]!.ToString());
        }
    }
    [Fact]
    public async Task WarmingAndStaleResponsesShareOneBackgroundRefreshAndKeepCachedData() {
        var rows = new Rows { Release = new(TaskCreationOptions.RunContinuationsAsynchronously) };
        var services = new ServiceCollection(); Services(services, rows, Config());
        await using var provider = services.BuildServiceProvider(); await using var scope = provider.CreateAsyncScope();
        var reader = scope.ServiceProvider.GetRequiredService<DashboardSnapshotReader>(); var cache = provider.GetRequiredService<DashboardSnapshotCache>();
        var warming = await reader.ReadAsync(false, Ct); await rows.Started.Task.WaitAsync(Ct);
        var refresh = cache.Refresh; var second = await reader.ReadAsync(false, Ct); Assert.Same(refresh, cache.Refresh);
        var expectedWarming = Reference()["cases"]![0]!["warming"]!.DeepClone();
        // Runtime is delegated to the Operations reader, outside snapshot composition.
        expectedWarming["health"]!["runtime"] = warming["health"]!["runtime"]!.DeepClone();
        Equal(expectedWarming, Normalize(warming)); Equal(Normalize(warming), Normalize(second));
        lock (cache.Sync) { cache.Payload = Reference()["cases"]![0]!["payload"]!.DeepClone().AsObject(); cache.Created = Stopwatch.GetTimestamp() - Stopwatch.Frequency * 20; }
        var stale = await reader.ReadAsync(false, Ct); Equal(Reference()["cases"]![0]!["stale"], Normalize(stale)); Assert.Same(refresh, cache.Refresh);
        stale["sources"]!["items"]![0]!["label"] = "changed";
        Assert.Contains("<script>", cache.Payload!["sources"]!["items"]![0]!["label"]!.ToString());
        rows.Release.TrySetResult(); await refresh!.WaitAsync(Ct);
        Assert.False((await reader.ReadAsync(false, Ct))["diagnostics"]!["stale"]!.GetValue<bool>());
    }
    [Fact]
    public async Task FailedComponentReturnsPartialWithoutLosingOtherDataAndCancellationPropagates() {
        var rows = new Rows { FailEntities = true }; var services = new ServiceCollection(); Services(services, rows, Config());
        await using var provider = services.BuildServiceProvider(); await using var scope = provider.CreateAsyncScope();
        var reader = scope.ServiceProvider.GetRequiredService<DashboardSnapshotReader>();
        var result = await reader.ReadAsync(true, Ct);
        Assert.Equal("partial", result["status"]!.ToString()); Assert.Equal("warn", result["health"]!["status"]!.ToString());
        Equal(Reference()["cases"]![2]!["payload"]!["entity_summary"], result["entity_summary"]);
        Assert.Equal(9, int.Parse(result["events_summary"]!["total_events"]!.ToString()));
        Equal(Reference()["cases"]![2]!["payload"]!["diagnostics"]!["failures"], result["diagnostics"]!["failures"]);
        Assert.DoesNotContain("fixture failure", result.ToJsonString());
        rows.Release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(Ct); cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => reader.ReadAsync(true, cancellation.Token));
    }
    [Theory]
    [InlineData("1000", 1000)]
    [InlineData("999999999999999999999", 250000)]
    [InlineData("invalid", 50000)]
    public async Task EventSampleConfigurationMatchesPython(string configured, int expected) {
        var config = new ConfigurationBuilder().AddConfiguration(Config()).AddInMemoryCollection(new Dictionary<string, string?> {
            ["Sli:Legacy:ADLOG_DASHBOARD_RECENT_EVENT_SAMPLE"] = configured
        }).Build();
        var services = new ServiceCollection(); Services(services, new Rows(), config);
        await using var provider = services.BuildServiceProvider(); await using var scope = provider.CreateAsyncScope();
        var result = await scope.ServiceProvider.GetRequiredService<DashboardSnapshotReader>().ReadAsync(true, Ct);
        Assert.Equal(expected, result["events_summary"]!["recent_sample_size"]!.GetValue<int>());
        Assert.Equal(expected, result["events_summary"]!["security_24h_summary"]!["sample_size"]!.GetValue<int>());
    }
    sealed class Database(string dsn) : Sli.Server.Infrastructure.IPostgresConnectionFactory {
        public async Task<Npgsql.NpgsqlConnection> OpenAsync(CancellationToken ct) { var db = new Npgsql.NpgsqlConnection(dsn); await db.OpenAsync(ct); return db; }
    }
    [Fact]
    public async Task DashboardRowsUseCallerCancellationWithoutInstallingDatabaseTimeouts() {
        await using var pg = new Sli.Server.Tests.Agents.PostCollectionPostgres(); await pg.StartAsync(Ct);
        using var rows = new PostgresLegacyRows(new Database(pg.ConnectionString));
        var result = Assert.Single(await rows.QueryAsync("select current_setting('statement_timeout') as statement, current_setting('lock_timeout') as lock, @p0::int as value", [7], 0, Ct));
        Assert.Equal("0", result!["statement"]!.ToString()); Assert.Equal("0", result["lock"]!.ToString()); Assert.Equal(7, result["value"]!.GetValue<int>());
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(Ct); cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => rows.QueryAsync("select 1", [], 0, cancellation.Token));
    }
    [Theory]
    [InlineData("")]
    [InlineData("?force=1")]
    public async Task RuntimeFailureUsesTheStandard500Response(string query) {
        using var host = await Host(new Rows(), runtimeFailure: true); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/dashboard/snapshot" + query, Ct);
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(Ct))!;
        Assert.Equal("internal_server_error", body["error"]!.ToString()); Assert.NotNull(body["internal_error_id"]);
        Assert.DoesNotContain("Environment DC", body.ToJsonString());
    }
    [Fact]
    public async Task MissingArchiveStartIsInitializedFromStoredHistoryAndPreservedOnLaterReads() {
        await using var pg = new Sli.Server.Tests.Agents.PostCollectionPostgres(); await pg.StartAsync(Ct);
        await using var db = new Npgsql.NpgsqlConnection(pg.ConnectionString); await db.OpenAsync(Ct);
        await Sli.Server.Tests.Agents.PostCollectionPostgres.Sql(db, """
            create table archive_settings(key text primary key,value text,created_at timestamptz,updated_at timestamptz);
            create table collection_runs(run_started_at timestamptz);
            create table event_hot(event_id bigint,time_created_utc timestamptz);
            create table event_cold_facts(event_id bigint,time_created_utc timestamptz);
            create table event_cold_daily(first_seen_utc timestamptz);
            create table collection_channel_state(server_hostname text,channel text,last_successful_collection_utc timestamptz,last_event_time_utc timestamptz,last_event_record_id bigint,backfill_completed boolean);
            insert into collection_runs values('2026-01-02T00:00:00Z');
            insert into event_cold_facts values(1,'2026-01-01T00:00:00Z');
            """, Ct);
        var services = new ServiceCollection(); Services(services, new Rows(), Config());
        services.AddScoped<ILegacyRows>(s => new PostgresLegacyRows(new Database(pg.ConnectionString)));
        await using var provider = services.BuildServiceProvider(); await using var scope = provider.CreateAsyncScope();
        var reader = scope.ServiceProvider.GetRequiredService<DashboardSnapshotReader>();
        var result = await reader.ReadAsync(true, Ct);
        Assert.Equal("2026-01-01 00:00:00+00", result["health"]!["archive_start_utc"]?.ToString());
        await Sli.Server.Tests.Agents.PostCollectionPostgres.Sql(db, "insert into event_hot values(2,'2025-01-01T00:00:00Z')", Ct);
        var second = await reader.ReadAsync(true, Ct);
        Assert.Equal(result["health"]!["archive_start_utc"]!.ToString(), second["health"]!["archive_start_utc"]?.ToString());
        await Sli.Server.Tests.Agents.PostCollectionPostgres.Sql(db, "truncate archive_settings,collection_runs,event_hot,event_cold_facts,event_cold_daily", Ct);
        var before = DateTimeOffset.UtcNow;
        var empty = await reader.ReadAsync(true, Ct);
        Assert.True(DateTimeOffset.TryParse(empty["health"]!["archive_start_utc"]?.ToString(), out var start));
        Assert.InRange(start, before, DateTimeOffset.UtcNow);
    }
}
