using System.Net;
using System.Text.Json;
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
using Sli.Server.Agents.Consumer;
using Sli.Server.Agents.SnapshotPublication;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Compatibility;
using Sli.Server.Legacy;
using Sli.Server.Problems;
using Sli.Server.Reporting.V2;
using Sli.Server.Vpn;
using Sli.Server.Workspace;
using Sli.Server.Operations;
using Sli.Server.Tests.Problems;
using Sli.Server.Tests.Reporting;
using Xunit;

namespace Sli.Server.Tests;

public sealed class TransferGapTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    sealed class Auth(string role, bool loggedIn) : IPrincipalAuthenticator {
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext c, CancellationToken ct) => ValueTask.FromResult(loggedIn ? AuthenticationResult.Success(new("session", 1, role)) : AuthenticationResult.Denied(401, "authentication_required"));
    }
    sealed class Facts(bool allowed) : IAccessFactsRepository {
        public Task<AccessFacts> LoadAsync(Principal p, CancellationToken ct) => Task.FromResult(new AccessFacts(false, p.Role, [], [], allowed ? new[] { "workspace.view", "investigations.view", "operations.view" }.Select(key => JsonSerializer.SerializeToElement(new { capability_key = key, effect = "allow", scope_json = new { kind = "all" } })).ToArray() : [], [], [], [], []));
    }
    sealed class WorkspaceReader : IWorkspaceCompatibilityReader {
        public int Calls;
        public Task<JsonObject> ReadAsync(string path, IQueryCollection q, Principal p, AccessReadEvaluation access, CancellationToken ct) { Calls++; return Task.FromResult(new JsonObject { ["route"] = path }); }
    }
    static async Task<IHost> Start(WorkspaceReader reader, bool allowed = true, string role = "operator", bool loggedIn = true) {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:AuthRequired"] = "1" }).Build();
        return await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(s => {
            s.AddRouting(); s.AddLogging(); s.AddSingleton<IConfiguration>(config); s.AddSingleton(new AuthRequestPolicy(config)); s.AddSingleton(new TransportGate(config));
            s.AddSingleton<IPrincipalAuthenticator>(new Auth(role, loggedIn)); s.AddSingleton<IAccessFactsRepository>(new Facts(allowed)); s.AddSingleton<IWorkspaceCompatibilityReader>(reader);
        }).Configure(app => { app.UseRouting(); app.UseReadRoleRequestGate(); app.UseEndpoints(e => { e.MapWorkspaceCompatibility(); e.MapLegacyHttp(); }); })).StartAsync(Ct);
    }
    public static TheoryData<string> ApiPaths => new(WorkspaceCompatibilityEndpoints.Routes);
    public static TheoryData<string, string, bool> HtmlPaths => new() {
        { "/reports/collector-health.html", "/app/operations", true }, { "/reports/autocollection.html", "/app/operations", true },
        { "/reports/diagnostics.html", "/app/operations", true },
        { "/reports/storage-health.html", "/app/operations", true }, { "/reports/system-health.html", "/app/operations", true },
        { "/reports/investigation.html", "/app/investigations", false }, { "/reports/role-overview.html", "/app/settings", false }, { "/reports/ui-navigation.html", "/app/settings", false }
    };
    [Theory, MemberData(nameof(ApiPaths))]
    public async Task NewApisDispatchAndDenyBeforeReadersAndInput(string path) {
        var reader = new WorkspaceReader();
        using (var host = await Start(reader)) { using var client = host.GetTestClient(); using var response = await client.GetAsync(path, Ct); Assert.Equal(HttpStatusCode.OK, response.StatusCode); Assert.Equal(1, reader.Calls); }
        reader.Calls = 0;
        using (var host = await Start(reader, false)) { using var client = host.GetTestClient(); using var response = await client.GetAsync(path + "?limit=bad", Ct); Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); Assert.Equal(0, reader.Calls); }
        using (var host = await Start(reader, loggedIn: false)) { using var client = host.GetTestClient(); using var response = await client.GetAsync(path, Ct); Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode); Assert.Equal(0, reader.Calls); }
    }
    [Theory, MemberData(nameof(HtmlPaths))]
    public async Task NewBookmarksPreserveRedirectsCapabilitiesRolesAndIgnoreInvalidUnusedInput(string path, string target, bool operatorOnly) {
        using (var host = await Start(new())) { using var client = host.GetTestClient(); using var response = await client.GetAsync(path + "?q=a%26b&limit=bad&force=bad", Ct); Assert.Equal(HttpStatusCode.Found, response.StatusCode); Assert.Equal(target + "?q=a%26b", response.Headers.Location!.ToString()); }
        using (var host = await Start(new(), false)) { using var client = host.GetTestClient(); using var response = await client.GetAsync(path, Ct); Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); }
        using (var host = await Start(new(), role: "viewer")) { using var client = host.GetTestClient(); using var response = await client.GetAsync(path, Ct); Assert.Equal(HttpStatusCode.Found, response.StatusCode); Assert.Equal(operatorOnly ? "/" : target, response.Headers.Location!.ToString()); }
        using (var host = await Start(new(), loggedIn: false)) { using var client = host.GetTestClient(); using var response = await client.GetAsync(path, Ct); Assert.Equal(HttpStatusCode.Found, response.StatusCode); Assert.StartsWith("/login?next=", response.Headers.Location!.ToString()); }
    }
    [Fact]
    public void FrozenNavigationAndParityResourcesLoadFromAssemblyAndAgreeWithRoutes() {
        var nav = LegacyWorkspaceModels.Navigation(new ConfigurationBuilder().Build());
        Assert.Equal(16, nav["items"]!.AsArray().Count); Assert.Equal(3, nav["roles"]!.AsArray().Count);
        var parity = LegacyWorkspaceModels.Parity(); Assert.Equal("accepted", parity["status"]!.ToString());
        foreach (var item in parity["mapped_routes"]!.AsArray().Where(n => n!["react_path"]!.ToString() is "/app/operations" or "/app/settings" or "/app/investigations")) Assert.Equal(item!["react_path"]!.ToString(), LegacyHttpEndpoints.Redirect(item["legacy_path"]!.ToString(), new QueryCollection()));
    }
    sealed class LegacyReader : ILegacyHttpReader {
        public int Calls; public LegacyQuery? Last;
        public Task<JsonObject> ReadAsync(string path, LegacyQuery q, CancellationToken ct) { Calls++; Last = q; return Task.FromResult(JsonNode.Parse("""{"items":[{"id":7,"event_id":4728,"time_created_utc":"2026-11-06T00:00:00Z","server":"dc.example.test","channel":"Security","target":"fixture"}],"returned_count":1,"total":null,"has_more":false}""")!.AsObject()); }
    }
    [Fact]
    public async Task EmptyInvestigationDoesNotReadGlobalEvidenceAndBadLimitFailsBeforeReads() {
        var source = new LegacyReader(); var reader = new LegacyInvestigationReader(source, new ProblemEndpointTests.Repository());
        var result = await reader.ReadAsync(new QueryCollection(), Ct); Assert.True(result["empty_query"]!.GetValue<bool>()); Assert.Empty(result["timeline"]!["chain"]!.AsArray()); Assert.Equal(0, source.Calls);
        await Assert.ThrowsAsync<FormatException>(() => reader.ReadAsync(new QueryCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues> { ["limit"] = "bad" }), Ct)); Assert.Equal(0, source.Calls);
        await Assert.ThrowsAsync<LegacyInputException>(() => reader.ReadAsync(new QueryCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues> { ["q"] = "fixture", ["time_from"] = "bad" }), Ct)); Assert.Equal(0, source.Calls);
    }
    [Theory]
    [InlineData("")]
    [InlineData(" \t\r\n ")]
    public async Task EmptyInvestigationReturnsStartScreenWithoutGlobalCountsOrFindings(string query) {
        // The legacy HTML bookmark redirects to React; the .NET start-screen
        // contract is the workspace payload consumed by that UI.
        var source = new LegacyReader();
        var reader = new LegacyInvestigationReader(source, new ProblemEndpointTests.Repository());
        var result = await reader.ReadAsync(new QueryCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues> { ["q"] = query }), Ct);
        Assert.True(result["empty_query"]!.GetValue<bool>());
        Assert.Equal("", result["q"]!.ToString());
        Assert.Empty(result["search"]!["items"]!.AsArray());
        Assert.Null(result["search"]!["total"]);
        Assert.Equal(0, result["search"]!["returned_count"]!.GetValue<int>());
        Assert.False(result["search"]!["has_more"]!.GetValue<bool>());
        Assert.Empty(result["timeline"]!["chain"]!.AsArray());
        Assert.Empty(result["timeline"]!["grouped"]!.AsObject());
        Assert.Empty(result["findings"]!["items"]!.AsArray());
        Assert.Empty(result["findings"]!["summary"]!.AsArray());
        foreach (string key in new[] { "total_events", "chain_events", "findings" }) Assert.Equal(0, result["summary"]![key]!.GetValue<int>());
        Assert.Null(result["summary"]!["first_event_utc"]);
        Assert.Null(result["summary"]!["last_event_utc"]);
        Assert.Empty(result["pivots"]!.AsArray());
        Assert.Equal("Введите объект расследования.", result["summary"]!["story"]!.ToString());
        Assert.NotEmpty(result["next_checks"]!.AsArray());
        Assert.DoesNotContain("320795", result.ToJsonString());
        Assert.Equal(0, source.Calls);
    }
    [Fact]
    public async Task LegacyInvestigationBuildsTypedTimelineAndHonestCoverageFromStoredEvents() {
        var source = new LegacyReader(); var reader = new LegacyInvestigationReader(source, new ProblemEndpointTests.Repository());
        var result = await reader.ReadAsync(new QueryCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues> { ["q"] = "fixture", ["limit"] = "999999999999999999999", ["scope"] = "all" }), Ct);
        Assert.Equal(2000, result["limit"]!.GetValue<int>()); Assert.Equal(1, result["summary"]!["chain_events"]!.GetValue<int>()); Assert.Equal("высокий", result["summary"]!["attention_level"]!.ToString());
        var item = Assert.Single(result["timeline"]!["chain"]!.AsArray()); Assert.Equal(7, item!["event_db_id"]!.GetValue<long>()); Assert.Equal("groups", item["category"]!.ToString()); Assert.Null(result["data_quality"]!["total_events"]); Assert.False(result["data_quality"]!["total_is_exact"]!.GetValue<bool>());
        Assert.True(source.Last!.Filters["include_internal_evidence"]!.GetValue<bool>());
    }
    [Fact]
    public async Task WorkspaceSourcePreservesPureResponses() {
        var config = new ConfigurationBuilder().Build(); var reader = new WorkspaceCompatibilityReader(null!, config, null!, null!, null!);
        var facts = new AccessFacts(false, "viewer", [], [], [], [], [], [], []); var caps = new CapabilityComposer().Compose(facts); var evaluation = new AccessReadEvaluation(facts, caps, new ReportEligibility().Compose(facts, caps));
        Assert.Equal("UI_NAVIGATION", (await reader.ReadAsync("/api/ui/navigation", new QueryCollection(), new("session", 1, "viewer"), evaluation, Ct))["package_type"]!.ToString());
    }
    sealed class WorkspaceRows : IWorkspaceRows {
        public Task<IReadOnlyList<JsonElement>> ReadAsync(string sql, CancellationToken ct, params Npgsql.NpgsqlParameter[] parameters) => Task.FromResult<IReadOnlyList<JsonElement>>([
            JsonSerializer.SerializeToElement(new { id = 1, object_type = "user", display_name = "fixture", natural_key = "private fixture key", last_seen_utc = "2026-11-06T00:00:00Z", domain_id = (long?)7, server_id = (long?)null }),
            JsonSerializer.SerializeToElement(new { id = 2, object_type = "user", display_name = "outside fixture", natural_key = "outside", last_seen_utc = "2026-11-06T00:00:00Z", domain_id = (long?)8, server_id = (long?)null }),
            JsonSerializer.SerializeToElement(new { id = 3, object_type = "user", display_name = "unknown fixture", natural_key = "unknown", last_seen_utc = "2026-11-06T00:00:00Z", domain_id = (long?)null, server_id = (long?)null })]);
    }
    [Fact]
    public async Task WorkspaceRecentObjectsApplyResourceAndTechnicalFieldGates() {
        var config = new ConfigurationBuilder().Build();
        var facts = new AccessFacts(false, "viewer", [], [], [JsonSerializer.SerializeToElement(new { capability_key = "objects.view", effect = "allow", scope_json = new { kind = "domain", ids = new[] { 7 } } })], [], [], [], []);
        var caps = new CapabilityComposer().Compose(facts); var evaluation = new AccessReadEvaluation(facts, caps, new ReportEligibility().Compose(facts, caps));
        var reader = new WorkspaceCompatibilityReader(new WorkspaceRows(), config, null!, null!, null!);
        var result = await reader.ReadAsync("/api/v1/workspace", new QueryCollection(), new("session", 1, "viewer"), evaluation, Ct);
        var recent = Assert.Single(result["recent_objects"]!.AsArray()); Assert.Equal("1", recent!["object_id"]!.ToString()); Assert.Null(recent["natural_key"]); Assert.DoesNotContain("outside fixture", result.ToJsonString()); Assert.DoesNotContain("private fixture key", result.ToJsonString());
    }
    sealed class SnapshotRows : ILegacyRows, IOperationsQueries {
        public int Calls;
        public Task<JsonArray> QueryAsync(string sql, IReadOnlyList<object> parameters, int timeoutMs, CancellationToken ct) {
            Interlocked.Increment(ref Calls);
            return Task.FromResult(sql.Contains("as events_total") ? JsonNode.Parse("""[{"events_total":12,"entities_total":3}]""")!.AsArray() : sql.Contains("as channel,coalesce") ? JsonNode.Parse("""[{"channel":"Security","count":12}]""")!.AsArray() : sql.Contains("as count from pg_class") ? JsonNode.Parse("""[{"count":6}]""")!.AsArray() : new JsonArray());
        }
        public Task<JsonArray> ReadAsync(string sql, CancellationToken ct, params (string Name, object? Value)[] parameters) => Task.FromResult(new JsonArray());
        public Task<JsonArray> HistoryAsync(string sql, IReadOnlyDictionary<string, string> parameters, CancellationToken ct) => throw new InvalidOperationException("not a history read");
        public Task<Dictionary<long, JsonObject>> HistoryEventsAsync(long[] ids, CancellationToken ct) => throw new InvalidOperationException("not a history read");
    }
    sealed class Files(IConfiguration config) : OperationsFiles(config) {
        public override JsonObject? Json(string relative, int maxBytes = 2097152) => null;
        public override JsonObject? PluginHeartbeat(string component) => null;
        public override JsonObject? NativeHeartbeat(string name) => null;
        public override JsonArray LogTail(string name, int lines) => new();
    }
    [Fact]
    public async Task DashboardBuildUsesBoundedSourcesAndFreshCacheDoesNotRepeatReads() {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:DataDirectory"] = Path.Combine(Path.GetTempPath(), "sli-gap-fixture-" + Guid.NewGuid().ToString("N")) }).Build();
        var source = new SnapshotRows(); var services = new ServiceCollection(); services.AddLogging(); services.AddSingleton<IConfiguration>(config); services.AddSingleton<ILegacyRows>(source); services.AddSingleton<IOperationsQueries>(source); services.AddSingleton<OperationsFiles>(new Files(config)); services.AddSingleton<OperationsCatalog>(); services.AddSingleton<OperationsJobs>(); services.AddSingleton(TimeProvider.System); services.AddScoped<OperationsService>(); services.AddSingleton<LegacySettings>(); services.AddSingleton<LegacyJobStore>(); services.AddSingleton<ILegacyHttpReader>(new LegacyReader()); services.AddWorkspaceCompatibility();
        await using var provider = services.BuildServiceProvider(); await using var scope = provider.CreateAsyncScope(); var reader = scope.ServiceProvider.GetRequiredService<DashboardSnapshotReader>();
        var cache = provider.GetRequiredService<DashboardSnapshotCache>(); cache.LastError = "previous_failure";
        var built = await reader.ReadAsync(true, Ct); Assert.Equal(12, built["events_summary"]!["total_events"]!.GetValue<long>()); Assert.Equal(3, built["role_views"]!["views"]!.AsArray().Count); Assert.Equal(14, built["reports"]!["items"]!.AsArray().Count);
        Assert.Null(cache.LastError);
        int calls = source.Calls; var cached = await reader.ReadAsync(false, Ct); Assert.True(cached["diagnostics"]!["cache_hit"]!.GetValue<bool>()); Assert.Equal(calls, source.Calls);
        var cards = await reader.ReadRoleViewsAsync(Ct);
        Assert.True(JsonNode.DeepEquals(built["role_views"], cards)); Assert.Equal(calls, source.Calls);
        cards["summary"]!["total_events"] = -1;
        Assert.Equal(12, (await reader.ReadRoleViewsAsync(Ct))["summary"]!["total_events"]!.GetValue<long>());
        lock (cache.Sync) { cache.Payload = null; cache.LastError = "previous_failure"; }
        var warming = await reader.ReadAsync(false, Ct);
        // Parity: tests/reporting/test_dashboard_warming_contract.py.
        Assert.Equal("warming", warming["status"]!.ToString());
        Assert.Equal("warming", warming["health"]!["status"]!.ToString());
        Assert.True(warming["diagnostics"]!["refreshing"]!.GetValue<bool>());
        await cache.Refresh!.WaitAsync(Ct);
        Assert.Null(cache.LastError);
    }
    sealed class Evidence : ISecurityProblemEvidence {
        public int Calls;
        public Task<JsonObject> PageAsync(ReportQueryContext c, long id, JsonObject? cursor, CancellationToken ct) { Calls++; return Task.FromResult(JsonNode.Parse("""{"items":[{"evidence_id":9,"event_db_id":null,"storage_kind":"core_event"}],"has_more":false,"total":1,"watermark":"2026-11-06T00:00:00Z"}""")!.AsObject()); }
    }
    sealed class NoDatabase : Sli.Server.Infrastructure.IPostgresConnectionFactory {
        public Task<Npgsql.NpgsqlConnection> OpenAsync(CancellationToken ct) => throw new InvalidOperationException("unexpected_database_read");
    }
    sealed class TestDatabase(string dsn) : Sli.Server.Infrastructure.IPostgresConnectionFactory {
        public async Task<Npgsql.NpgsqlConnection> OpenAsync(CancellationToken ct) { var db = new Npgsql.NpgsqlConnection(dsn); await db.OpenAsync(ct); return db; }
    }
    [Fact]
    public async Task SecurityDetailRechecksOpenPopulationBeforeReadingEvidence()
    {
        await using var pg = new Sli.Server.Tests.Agents.PostCollectionPostgres(); await pg.StartAsync(Ct);
        await using var db = new Npgsql.NpgsqlConnection(pg.ConnectionString); await db.OpenAsync(Ct);
        await Sli.Server.Tests.Agents.PostCollectionPostgres.Sql(db, """
            create table findings_active(id bigint,rule_code text,status text,severity text,repeat_count integer,last_seen_utc text,updated_at timestamptz);
            insert into findings_active values(7,'fixture.rule','closed','high',0,'2026-11-06T00:00:00Z',now()),(8,'fixture.rule','false_positive','high',0,'2026-11-06T00:00:00Z',now());
            create table auth_users(id bigint,username text);
            create table semantic_suppressions(id bigint,finding_id bigint,kind text,responsible_user_id bigint,
                state text,expires_at timestamptz,semantic_type text not null);
            create table semantic_control_audit(id bigint,action text,actor text,occurred_at timestamptz,details jsonb);
            create function is_semantic_finding_published_v1(bigint) returns boolean language sql as $$select true$$;
            create function semantic_finding_in_domains_v265(bigint,bigint[]) returns boolean language sql as $$select true$$;
            create function semantic_finding_suppressed_v160(bigint,text) returns boolean language sql as $$select false$$;
            create function semantic_finding_review_v160(bigint) returns jsonb language sql as $$select null::jsonb$$;
            create function finding_decoy_context(bigint) returns jsonb language sql as $$select null::jsonb$$;
            """, Ct);
        var evidence = new Evidence();
        var repository = new ProblemRepository(new TestDatabase(pg.ConnectionString), TimeProvider.System);
        await using var host = await ReportFixture.Start(ProblemEndpointTests.Facts(), new ReportDefinitionRegistry().Get("security.problems")!, nativeReader: new SecurityProblemsReader(repository, evidence));
        foreach (long id in new long[] { 7, 8 }) {
            using var response = await host.Client.GetAsync($"/api/v2/reports/security.problems/rows/{id}/detail", Ct);
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            Assert.Contains("report_row_not_found", (await ReportFixture.Body(response)).ToJsonString());
        }
        Assert.Equal(0, evidence.Calls);
        foreach (string query in new[] { "population=all", "id=7", "status=closed", "risk=all" }) {
            using var response = await host.Client.GetAsync("/api/v2/reports/security.problems/rows/7/detail?" + query, Ct);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
        Assert.Equal(4, evidence.Calls);
        await Sli.Server.Tests.Agents.PostCollectionPostgres.Sql(db, "update findings_active set status='active' where id=7", Ct);
        using (var open = await host.Client.GetAsync("/api/v2/reports/security.problems/rows/7/detail", Ct))
            Assert.Equal(HttpStatusCode.OK, open.StatusCode);
        Assert.Equal(5, evidence.Calls);
        host.Facts.Value = ProblemEndpointTests.Facts(false);
        using var denied = await host.Client.GetAsync("/api/v2/reports/security.problems/rows/7/detail?population=all", Ct);
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode); Assert.Equal(5, evidence.Calls);
    }

    [Fact]
    public async Task SecurityQueueUsesRegisteredNativeReaderAndScopedDetailAndDeniesInvalidInput() {
        var repo = new ProblemEndpointTests.Repository(); var evidence = new Evidence(); var definition = new ReportDefinitionRegistry().Get("security.problems")!;
        await using var host = await ReportFixture.Start(ProblemEndpointTests.Facts(), definition, nativeReader: new SecurityProblemsReader(repo, evidence));
        using (var response = await host.Client.GetAsync("/api/v2/reports/security.problems/data?tab=table", Ct)) {
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var body = await ReportFixture.Body(response);
            Assert.Equal("7", Assert.Single(body["items"]!.AsArray())!["id"]!.ToString());
            Assert.Contains(body["metrics"]!.AsArray(), metric => metric?["key"]?.ToString() == "open");
            Assert.Null(body["coverage"]!["password_detection"]);
            Assert.DoesNotContain(body["limitations"]!.AsArray(), limitation => limitation?["code"]?.ToString() == "password_coverage_incomplete");
        }
        using (var response = await host.Client.GetAsync("/api/v2/reports/security.problems/rows/7/detail", Ct)) { Assert.Equal(HttpStatusCode.OK, response.StatusCode); Assert.Equal("partial", (await ReportFixture.Body(response))["state"]!.ToString()); Assert.Equal(1, evidence.Calls); }
        int before = repo.Calls;
        using (var response = await host.Client.GetAsync("/api/v2/reports/security.problems/data?severity=invalid", Ct)) Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using (var response = await host.Client.GetAsync("/api/v2/reports/security.problems/data?time_from=bad&time_to=bad", Ct)) Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(before, repo.Calls);
        host.Facts.Value = ProblemEndpointTests.Facts(false);
        using (var response = await host.Client.GetAsync("/api/v2/reports/security.problems/data?limit=bad", Ct)) Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(before, repo.Calls);
    }
    [Fact]
    public async Task ExactHardeningRouteDelegatesOtherTabsToTheEngine() {
        var repo = new ProblemEndpointTests.Repository(); var evidence = new Evidence();
        var facts = ProblemEndpointTests.Facts();
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:AuthRequired"] = "1" }).Build();
        using var host = await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(s => {
            s.AddRouting(); s.AddLogging(); s.AddSingleton<IConfiguration>(config); s.AddSingleton(new AuthRequestPolicy(config)); s.AddSingleton(new TransportGate(config));
            s.AddSingleton<IPrincipalAuthenticator>(new Auth("admin", true)); s.AddSingleton<IAccessFactsRepository>(new ReportFixture.FactsRepo(facts));
            s.AddSingleton<IProblemRepository>(repo); s.AddSingleton<ISecurityProblemEvidence>(evidence); s.AddSingleton<IReportV2Metadata>(new ReportFixture.Metadata());
            s.AddSingleton<Sli.Server.Infrastructure.IPostgresConnectionFactory>(new NoDatabase());
            Sli.Server.Reporting.ReportStudioEndpoints.AddReportStudio(s);
            Sli.Server.Storage.EventReports.EventReadEndpoints.AddEventReads(s);
            Sli.Server.Ad.AdReportEndpoints.AddAdReports(s);
            s.AddReportV2Engine();
        }).Configure(app => { app.UseRouting(); app.UseEndpoints(e => { e.MapReportV2Engine(); Sli.Server.Reports.AdHardeningEndpoints.MapAdHardening(e); }); })).StartAsync(Ct);
        using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/v2/reports/security.problems/data?tab=table", Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); Assert.Equal(1, repo.Calls); Assert.Single((await ReportFixture.Body(response))["items"]!.AsArray());
    }
    [Fact]
    public async Task PostCollectionRunsOptionalLegacyUnderTheSameSerialLoopAndPropagatesFailure() {
        var calls = new List<string>(); JsonObject? last = null;
        Task<PostCollectionBatch> Poll(string owner) { calls.Add(owner); return Task.FromResult(PostCollectionBatch.Empty); }
        var loop = new PostCollectionLoop(_ => Poll("events"), _ => Poll("snapshots"), _ => Poll("accounting"), (_, _, _, _) => Task.CompletedTask, () => TimeSpan.Zero, Task.Delay, r => last = r,
            _ => { calls.Add("legacy"); return Task.FromResult(new LegacyPostResult(1, 0, 1)); });
        Assert.Equal(1, await loop.RunAsync(new(true, 10), Ct)); Assert.Equal(new[] { "events", "snapshots", "legacy", "accounting" }, calls);
        Assert.Equal(1, last!["last_result"]!["failed"]!.GetValue<int>());
    }
    [Fact]
    public async Task LegacyOnceKeepsReferenceExitContractForAnIsolatedAgentFailure() {
        var loop = new PostCollectionLoop(_ => throw new InvalidOperationException("source unavailable"), _ => Task.FromResult(PostCollectionBatch.Empty), _ => Task.FromResult(PostCollectionBatch.Empty), (_, _, _, _) => Task.CompletedTask, () => TimeSpan.Zero, Task.Delay,
            legacy: _ => Task.FromResult(new LegacyPostResult(0, 0, 0)));
        Assert.Equal(0, await loop.RunAsync(new(true, 10), Ct));
    }
    [Fact]
    public async Task NewCommandParsersRejectUnknownInputBeforeReadingConfiguration() {
        Assert.Equal(2, await RadiusObservationHost.RunAsync(["--unknown-gap-option"]));
        Assert.Equal(2, await AdCoordinatorCommand.RunAsync(["--unknown-gap-option"]));
        Assert.Equal(0, await RadiusObservationHost.RunAsync(["--help"]));
        Assert.Equal(0, await AdCoordinatorCommand.RunAsync(["--help"]));
    }
    [Fact]
    public async Task CohortSqlGroupsBeforePagingKeepsUrgentRepresentativeAndMaximumIdCursor() {
        await using var pg = new Sli.Server.Tests.Agents.PostCollectionPostgres(); await pg.StartAsync(Ct);
        await using var db = new Npgsql.NpgsqlConnection(pg.ConnectionString); await db.OpenAsync(Ct);
        await Sli.Server.Tests.Agents.PostCollectionPostgres.Sql(db, """
            create function public.password_problem_facts395(bigint,text) returns jsonb language sql as $$select null::jsonb$$;
            create temp table finding_event_details337(finding_id bigint,event_db_id bigint,event_id integer);
            create temp table finding_entities(finding_id bigint,display_name text,entity_role text);
            create temp table semantic_security_scenarios(scenario_key bytea,scenario_kind text,partition_key text,strict_keys_json jsonb);
            create temp table findings_fixture(id bigint,rule_code text,actor text,target text,first_seen_utc text,last_seen_utc text,evidence_count integer,severity text,status text);
            insert into findings_fixture values
              (1,'fixture.rule','fixture actor','fixture target','2026-11-06T00:00:00Z','2026-11-06T00:00:00Z',0,'high','new'),
              (3,'fixture.rule','fixture actor','fixture target','2026-11-06T00:00:00Z','2026-11-06T00:00:00Z',0,'low','active'),
              (2,'fixture.rule','','','2026-11-06T00:00:00Z','2026-11-06T00:00:00Z',0,'medium','new');
            alter table findings_fixture add column fingerprint text,add column source text,add column repeat_count integer default 0;
            """, Ct);
        string prefix = ProblemCohorts.Queue("from findings_fixture findings", " where true", "findings.status", "false");
        await using var command = new Npgsql.NpgsqlCommand(prefix + "select id,occurrence_count,queue_cursor_id,problem_cohort from queue_groups order by queue_cursor_id desc", db);
        command.Parameters.AddWithValue("cohort_zone", "UTC");
        await using var rows = await command.ExecuteReaderAsync(Ct);
        Assert.True(await rows.ReadAsync(Ct)); Assert.Equal(1, rows.GetInt64(0)); Assert.Equal(2, rows.GetInt64(1)); Assert.Equal(3, rows.GetInt64(2));
        Assert.True(await rows.ReadAsync(Ct)); Assert.Equal(2, rows.GetInt64(0)); Assert.False(await rows.ReadAsync(Ct));
    }
    [Fact]
    public async Task RadiusChildLoginHasOnlyConsumerMembershipAndIsRevokedAfterFailure() {
        await using var pg = new Sli.Server.Tests.Agents.PostCollectionPostgres(); await pg.StartAsync(Ct);
        await using var admin = new Npgsql.NpgsqlConnection(pg.ConnectionString); await admin.OpenAsync(Ct);
        await Sli.Server.Tests.Agents.PostCollectionPostgres.Sql(admin, "create role adlog_radius_session_consumer", Ct);
        string? role = null;
        await Assert.ThrowsAsync<InvalidOperationException>(() => RadiusObservationHost.WithConsumerLogin(new TestDatabase(pg.ConnectionString), async dsn => {
            var settings = new Npgsql.NpgsqlConnectionStringBuilder(dsn); role = settings.Username;
            Assert.StartsWith("adlog_radius_consumer_", role); Assert.False(settings.Pooling); Assert.False(settings.Multiplexing);
            await using var child = new Npgsql.NpgsqlConnection(dsn); await child.OpenAsync(Ct);
            await using (var check = new Npgsql.NpgsqlCommand("select rolcreatedb,rolcreaterole,rolsuper,rolbypassrls,rolinherit from pg_roles where rolname=current_user", child))
            await using (var row = await check.ExecuteReaderAsync(Ct)) { Assert.True(await row.ReadAsync(Ct)); for (int i = 0; i < 5; i++) Assert.False(row.GetBoolean(i)); }
            var denied = await Assert.ThrowsAsync<Npgsql.PostgresException>(async () => { await using var read = new Npgsql.NpgsqlCommand("select * from sli_p04_test_owner", child); await read.ExecuteNonQueryAsync(Ct); }); Assert.Equal("42501", denied.SqlState);
            await using (var set = new Npgsql.NpgsqlCommand("set role adlog_radius_session_consumer", child)) await set.ExecuteNonQueryAsync(Ct);
            throw new InvalidOperationException("synthetic_cycle_failure");
        }, Ct));
        Assert.NotNull(role); await using var absent = new Npgsql.NpgsqlCommand("select not exists(select 1 from pg_roles where rolname=@role)", admin); absent.Parameters.AddWithValue("role", role); Assert.Equal(true, await absent.ExecuteScalarAsync(Ct));
    }
    [Fact]
    public async Task CoordinatorPublicationHonorsTheSharedProcessLockAndDueSlotOnAnEmptyInbox() {
        await using var pg = new Sli.Server.Tests.Agents.PostCollectionPostgres(); await pg.StartAsync(Ct);
        var due = AdCoordinatorLoop.Slot(DateTimeOffset.Parse("2026-11-06T13:00:00Z"));
        var empty = await GpoWorkerCommand.RunOnceAsync(pg.ConnectionString, null, "sli.ad-snapshot", Ct, due); Assert.Equal(0, empty.ExitCode); Assert.Equal(0, empty.Scanned);
        await using var holder = new Npgsql.NpgsqlConnection(pg.ConnectionString); await holder.OpenAsync(Ct);
        await using (var take = new Npgsql.NpgsqlCommand("select pg_advisory_lock(hashtext('ad_log_reports_runtime_post_collection_process'))", holder)) await take.ExecuteScalarAsync(Ct);
        try { Assert.Equal(9, (await GpoWorkerCommand.RunOnceAsync(pg.ConnectionString, null, "sli.ad-snapshot", Ct, due)).ExitCode); }
        finally { await using var release = new Npgsql.NpgsqlCommand("select pg_advisory_unlock(hashtext('ad_log_reports_runtime_post_collection_process'))", holder); await release.ExecuteScalarAsync(Ct); }
    }
    [Fact]
    public void RadiusControlBrokerUsesProtectedIdentityAndRejectsAmbiguousSecrets() {
        var values = new Dictionary<string, string?> { ["ADLOG_PG_DSN"] = "host=postgres.example.test dbname=sli user=fixture_reader password=fixture_core", ["ADLOG_PG_ADMIN_USER"] = "fixture_control", ["ADLOG_PG_ADMIN_PASSWORD_FILE"] = "synthetic-secret" };
        string? Get(string key) => values.GetValueOrDefault(key);
        var settings = RadiusHostConfiguration.Settings(new ConfigurationBuilder().Build(), Get, _ => "fixture_generated_password\n"u8.ToArray());
        Assert.Equal("fixture_reader", settings.Core.Username); Assert.Equal("fixture_control", settings.Broker.Username); Assert.False(settings.Broker.Pooling); Assert.False(settings.Broker.Multiplexing);
        values["ADLOG_PG_ADMIN_PASSWORD"] = "fixture_ambiguous";
        Assert.Equal("server_configuration_invalid:ADLOG_PG_ADMIN_PASSWORD_FILE:conflict", Assert.Throws<Sli.Server.Hosting.ServerConfigurationException>(
            () => RadiusHostConfiguration.Settings(new ConfigurationBuilder().Build(), Get, _ => throw new Exception("must reject before read"))).Message);
        values.Remove("ADLOG_PG_ADMIN_PASSWORD");
        values["ADLOG_PG_DSN"] = "host=postgres.example.test dbname=sli user=fixture_reader";
        values["ADLOG_PG_PASSWORD_FILE"] = "synthetic-core";
        settings = RadiusHostConfiguration.Settings(new ConfigurationBuilder().Build(), Get,
            path => System.Text.Encoding.UTF8.GetBytes(path == "synthetic-core" ? "synthetic-core-password" : "synthetic-broker-password"));
        Assert.Equal("synthetic-core-password", settings.Core.Password);
        Assert.Equal("synthetic-broker-password", settings.Broker.Password);
    }
    [Fact]
    public void RadiusChildRejectsCoreCredentialsAndNonEphemeralDatabaseIdentity() {
        var values = new Dictionary<string, string?> { ["SLI_PLUGIN_PG_DSN"] = "Host=postgres.example.test;Database=sli;Username=adlog_radius_consumer_0123456789abcdef;Password=fixture_generated;Pooling=false" };
        string? Get(string key) => values.GetValueOrDefault(key);
        var child = new Npgsql.NpgsqlConnectionStringBuilder(RadiusObservationHost.ChildDsn(Get));
        Assert.Equal("adlog_radius_consumer_0123456789abcdef", child.Username); Assert.Equal(0, child.CommandTimeout); Assert.False(child.Pooling);
        values["ADLOG_PG_ADMIN_PASSWORD"] = "fixture_prohibited";
        Assert.Equal("admin_database_environment_reached_plugin_child", Assert.Throws<InvalidOperationException>(() => RadiusObservationHost.ChildDsn(Get)).Message);
        values.Remove("ADLOG_PG_ADMIN_PASSWORD"); values["SLI_PLUGIN_PG_DSN"] = "Host=postgres.example.test;Database=sli;Username=fixture_admin;Password=fixture_prohibited;Pooling=false";
        Assert.Equal("consumer_worker_identity_invalid", Assert.Throws<InvalidOperationException>(() => RadiusObservationHost.ChildDsn(Get)).Message);
    }
    [Fact]
    public async Task RadiusHostRunsEveryThirtySecondsStopsWhenDisabledAndFailsClosed() {
        int cycles = 0; var phases = new List<string>();
        var loop = new RadiusObservationLoop(_ => Task.FromResult(cycles < 2), _ => { cycles++; return Task.CompletedTask; }, (p, _) => { phases.Add(p); return Task.CompletedTask; }, (wait, _) => { Assert.Equal(TimeSpan.FromSeconds(30), wait); return Task.CompletedTask; });
        Assert.Equal(0, await loop.RunAsync(false, Ct)); Assert.Equal(2, cycles); Assert.Equal(new[] { "cycle", "sleep", "cycle", "sleep", "disabled" }, phases);
        loop = new(_ => Task.FromResult(true), _ => throw new InvalidOperationException("private"), (p, _) => { phases.Add(p); return Task.CompletedTask; }, (_, _) => throw new Exception("no delay after failure"));
        Assert.Equal(1, await loop.RunAsync(false, Ct)); Assert.Equal("cycle_failed", phases[^1]);
        Assert.Equal(2, await RadiusObservationHost.RunAsync(["--component", "unknown-component", "--once"]));
    }
    [Fact]
    public async Task CoordinatorHasInitialDelayUtcSlotsBoundedWaitAndRetriesFailedCycles() {
        var now = DateTimeOffset.Parse("2026-11-06T10:56:30Z"); int cycles = 0; int waits = 0; var phases = new List<string>();
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        var loop = new AdCoordinatorLoop(() => now, (slot, _) => { Assert.Equal(cycles++ == 0 ? 23 : 11, slot.Hour); if (cycles == 2) stop.Cancel(); return Task.FromResult(1); }, (p, _, _) => { phases.Add(p); return Task.CompletedTask; }, (wait, _) => { if (waits++ == 0) Assert.Equal(TimeSpan.FromSeconds(180), wait); else Assert.InRange(wait.TotalSeconds, 1, 300); now += wait; return Task.CompletedTask; });
        Assert.Equal(0, await loop.RunAsync(false, false, stop.Token)); Assert.Equal(2, cycles); Assert.Equal("initial_delay", phases[0]); Assert.Contains("waiting_for_calendar_slot", phases);
        Assert.Equal(11, AdCoordinatorLoop.Slot(DateTimeOffset.Parse("2026-11-06T20:00:00+07:00")).Hour);
        loop = new(() => now, (_, _) => Task.FromResult(9), (_, _, _) => Task.CompletedTask, (_, _) => throw new Exception("once cannot wait")); Assert.Equal(0, await loop.RunAsync(true, false, Ct));
    }
}
