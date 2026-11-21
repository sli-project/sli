using System.Net;
using System.Text;
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
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Hosting;
using Sli.Server.Operations;
using Xunit;

namespace Sli.Server.Tests.Operations;

public sealed class OperationsEndpointTests
{
    internal static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-11-05T12:00:00Z");
    sealed class Clock : TimeProvider { public override DateTimeOffset GetUtcNow() => Now; }
    sealed class Auth(string role, bool authenticated) : IPrincipalAuthenticator
    { public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext context, CancellationToken ct) => ValueTask.FromResult(authenticated ? AuthenticationResult.Success(new("session", 1, role)) : AuthenticationResult.Denied(401, "authentication_required")); }
    sealed class Facts(bool allow, bool owner = false, string? effect = null, bool scoped = false) : IAccessFactsRepository
    {
        public Task<AccessFacts> LoadAsync(Principal principal, CancellationToken ct)
        {
            static JsonElement J(string s) => JsonDocument.Parse(s).RootElement.Clone();
            var caps = allow ? new[] { "operations.view", "administrative.activity.view" }.Select(k => J(new JsonObject { ["capability_key"] = k, ["effect"] = effect ?? "allow", ["scope_json"] = scoped ? new JsonObject { ["kind"] = "domain", ["ids"] = new JsonArray(1) } : new JsonObject { ["kind"] = "all" } }.ToJsonString())).ToArray() : [];
            return Task.FromResult(new AccessFacts(owner, principal.Role, [], [], caps, [], [], [], []));
        }
    }
    internal sealed class Files(IConfiguration config) : OperationsFiles(config)
    {
        public JsonObject? FootprintValue;
        public int FootprintReads, Scans, Inventories;
        public JsonObject? RuntimeStorageValue;
        public int RuntimeStorageReads;
        public JsonObject? CockpitStatus;
        public Dictionary<string, JsonObject> Native = new();
        public override JsonObject? Json(string relative, int maxBytes = 2097152) => relative == "data/maintenance/postgres_backup_restore_last.json" ? new() { ["status"] = "verified" } : null;
        public override JsonArray LogTail(string name, int lines) => [];
        internal override JsonObject? WebConsoleStatus() => CockpitStatus;
        internal override IEnumerable<string> CollectorLogLines() => [];
        public override JsonObject? PluginHeartbeat(string component) => null;
        public override JsonObject? NativeHeartbeat(string name) => Native.GetValueOrDefault(name)?.DeepClone().AsObject();
        public override JsonObject Footprint(DateTimeOffset now)
        {
            FootprintReads++;
            return FootprintValue?.DeepClone().AsObject() ?? new() { ["status"] = "unavailable", ["components"] = new JsonArray(), ["totals"] = new JsonObject(), ["warnings"] = new JsonArray("Complete storage footprint snapshot is unavailable."), ["snapshot"] = new JsonObject { ["available"] = false } };
        }
        public override JsonObject DiskPressure() => new() { ["status"] = "ok", ["collection_allowed"] = true, ["disk"] = new JsonObject { ["free_bytes"] = 1000000000000L, ["total_bytes"] = 2000000000000L } };
        public override JsonObject RuntimeStorage(bool force, DateTimeOffset now)
        {
            RuntimeStorageReads++;
            return RuntimeStorageValue?.DeepClone().AsObject() ?? new() { ["snapshot"] = new JsonObject { ["status"] = "warming", ["refreshing"] = true }, ["sizes"] = new JsonObject(), ["warnings"] = new JsonArray("Полный снимок хранилища формируется; частичные размеры не показываются") };
        }
        internal override JsonObject Scan(string relative, int maxEntries, TimeSpan budget, DateTimeOffset? modifiedSince = null)
        { Scans++; return new() { ["bytes"] = 0, ["human"] = "0 B", ["files"] = 0, ["scan"] = new JsonObject { ["complete"] = true } }; }
        internal override IReadOnlyList<FileInfo> Inventory(string relative, int maxEntries, TimeSpan budget)
        { Inventories++; return []; }
    }
    internal sealed class Queries : IOperationsQueries
    {
        public DateTimeOffset? LastEventTime;
        public JsonArray? SystemInventory;
        public int Reads; public bool Fail; public string? FailContaining; public JsonArray? Workers; public JsonArray? Inventory; public JsonArray? Radius; public JsonArray? PostSummary; public JsonArray? PostItems; public bool Ambiguous; public List<(string Sql, (string Name, object? Value)[] Parameters)> Calls = [];
        public Dictionary<string, JsonArray> Results = new();
        public Task<JsonArray> ReadAsync(string sql, CancellationToken ct, params (string Name, object? Value)[] parameters)
        {
            Reads++; Calls.Add((sql, parameters));
            if (Fail || FailContaining is not null && sql.Contains(FailContaining, StringComparison.Ordinal)) throw new InvalidOperationException("private-db-password-and-AD-data");
            if (Results.TryGetValue(sql, out var result)) return Task.FromResult(result.DeepClone().AsArray());
            JsonArray rows = [];
            if (sql.Contains("from post_collection_jobs group by status")) return Task.FromResult(PostSummary?.DeepClone().AsArray() ?? rows);
            if (sql.Contains("from post_collection_jobs order by id desc")) return Task.FromResult(PostItems?.DeepClone().AsArray() ?? rows);
            if (sql == OperationsSql.Sources)
            {
                rows = JsonNode.Parse("""[{"hostname":"DC1","fqdn":"dc1.example.test","role":"domain_controller","is_active":true,"os_name":null,"os_version":null,"domain_fqdn":"example.test","netbios_name":"EXAMPLE","site_name":"site"}]""")!.AsArray();
                if (Ambiguous) { var second = rows[0]!.DeepClone(); second["domain_fqdn"] = "other.test"; second["fqdn"] = "dc1.other.test"; rows.Add(second); }
            }
            else if (sql == OperationsSql.SourceInventory) rows = Inventory?.DeepClone().AsArray() ?? [];
            else if (sql.Contains("from pg_class c join pg_namespace")) rows = SystemInventory?.DeepClone().AsArray() ?? [];
            else if (sql.Contains("from domain_controller_targets")) rows = JsonNode.Parse("""[{"hostname":"DC1","connect_address":"dc1.example.test","enabled":true}]""")!.AsArray();
            else if (sql.Contains("from runtime_worker_heartbeats")) rows = Workers?.DeepClone().AsArray() ?? [];
            else if (sql.Contains("from radius_vpn_operations_v1")) rows = Radius?.DeepClone().AsArray() ?? [];
            else if (sql.Contains("as database_name")) rows.Add(new JsonObject { ["database_name"] = "fixture", ["database_bytes"] = 1000, ["checked_at"] = Now.ToString("O") });
            else if (sql.Contains("version() as version")) rows.Add(new JsonObject { ["database"] = "fixture", ["user"] = "fixture", ["version"] = "PostgreSQL fixture" });
            else if (sql.Contains("information_schema.tables")) rows = new JsonArray(new[] { "schema_migrations", "log_sources", "collection_channel_state", "collector_channel_runs", "collector_stage_metrics", "events", "findings", "ai_api_runs" }.Select(t => (JsonNode)new JsonObject { ["table_name"] = t }).ToArray());
            else if (sql == OperationsSql.CollectorState)
                rows.Add(new JsonObject { ["server_hostname"] = "DC1", ["channel"] = "Security", ["last_successful_collection_utc"] = Now.AddMinutes(-1).ToString("O"), ["last_event_time_utc"] = (LastEventTime ?? Now.AddDays(-1)).ToString("O"), ["updated_at"] = Now.ToString("O"), ["recovery_mode"] = false });
            else if (sql == OperationsSql.CollectorHistory) rows.Add(new JsonObject { ["server"] = "DC1", ["channel"] = "Security", ["last_status"] = "completed", ["timeouts_24h"] = 0 });
            else if (sql.Contains("storage_lifecycle_snapshots"))
                rows = new JsonArray(new JsonObject { ["captured_at"] = Now.ToString("O"), ["database_bytes"] = 2000, ["disk_total_bytes"] = 100000, ["disk_free_bytes"] = 70000 }, new JsonObject { ["captured_at"] = Now.AddDays(-1).ToString("O"), ["database_bytes"] = 1000 });
            return Task.FromResult(rows);
        }
    }
    internal sealed class App(IHost host, HttpClient client, Queries queries, Files files, OperationsJobs jobs) : IDisposable
    {
        public HttpClient Client = client; public Queries Queries = queries; public Files Files = files; public OperationsJobs Jobs = jobs;
        public void Dispose() { Client.Dispose(); host.Dispose(); }
        public OperationsService Service => host.Services.GetRequiredService<OperationsService>();
    }
    internal static async Task<App> Start(bool allow = true, string role = "admin", bool authenticated = true, bool owner = false, string? effect = null, bool scoped = false, Dictionary<string, string?>? settings = null, OperationsCatalog? catalog = null, Sli.Server.Legacy.LegacyJobStore? legacy = null, TimeProvider? clock = null, IOperationsQueries? postgresQueries = null)
    {
        var values = new Dictionary<string, string?> { ["Sli:AuthRequired"] = "true", ["Sli:Operations:SLI_LEGACY_COLLECTION_DISABLED"] = "1" };
        foreach (var entry in settings ?? []) values[entry.Key] = entry.Value;
        var config = new ConfigurationBuilder().AddInMemoryCollection(values).Build(); var queries = new Queries(); var files = new Files(config); var jobs = new OperationsJobs(legacy);
        jobs.Record(new JsonObject { ["id"] = 1, ["status"] = "completed", ["kind"] = "collect_all_dc_logs", ["errors"] = new JsonArray() });
        var host = await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(services =>
        {
            services.AddRouting(); services.AddLogging(); services.AddSingleton<IConfiguration>(config); services.AddSingleton(new AuthRequestPolicy(config)); services.AddSingleton(new TransportGate(config));
            services.AddSingleton<IPrincipalAuthenticator>(new Auth(role, authenticated)); services.AddSingleton<IAccessFactsRepository>(new Facts(allow, owner, effect, scoped));
            services.AddSingleton<IOperationsQueries>(postgresQueries ?? queries); services.AddSingleton<OperationsFiles>(files); services.AddSingleton(jobs); services.AddSingleton<TimeProvider>(clock ?? new Clock()); services.AddOperations();
            if (catalog is not null) services.AddSingleton(catalog);
        }).Configure(app => { app.UseRouting(); app.UseReadRoleRequestGate(); app.UseEndpoints(endpoints => { endpoints.MapOperations(); endpoints.MapSliHealth(); }); })).StartAsync(TestContext.Current.CancellationToken);
        return new(host, host.GetTestClient(), queries, files, jobs);
    }
    public static IEnumerable<object[]> Routes()
    {
        foreach (string path in OperationsEndpoints.GetRoutes) yield return ["GET", path.Replace("{hostname}", "DC1").Replace("{id}", "1"), path == "/api/v1/operations/administrative-activity" ? 503 : 200];
        yield return ["POST", "/api/v1/source-onboarding/preflight", 200];
    }
    internal static Task<HttpResponseMessage> Request(App app, string method, string path, string body = """{"hostname":"DC2","connect_address":"dc2.example.test","channels":["Security"]}""") => app.Client.SendAsync(new HttpRequestMessage(new HttpMethod(method), path) { Content = method == "POST" ? new StringContent(body, Encoding.UTF8, "application/json") : null }, TestContext.Current.CancellationToken);
    internal static async Task<JsonObject> Body(HttpResponseMessage response) => JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();

    [Theory]
    [InlineData("matching")]
    [InlineData("other-release")]
    [InlineData("missing")]
    public async Task Health_and_diagnostics_report_the_selected_release(string receiptState)
    {
        const string tag = "beta1-0123456789ab";
        const string commit = "0123456789abcdef0123456789abcdef01234567";
        const string installedAt = "2026-11-21T01:02:03.456789+00:00";
        var root = Directory.CreateTempSubdirectory("sli-release-test-");
        try
        {
            if (receiptState != "missing")
            {
                File.WriteAllText(Path.Combine(root.FullName, "native-package.json"),
                    new JsonObject { ["release"] = tag }.ToJsonString());
                File.WriteAllText(Path.Combine(root.FullName, "native-runtime.json"),
                    new JsonObject { ["provenance"] = new JsonObject { ["source_commit"] = commit } }.ToJsonString());
                File.WriteAllText(Path.Combine(root.FullName, "sli-installation"), new JsonObject
                {
                    ["release"] = receiptState == "matching" ? root.FullName : Path.Combine(root.FullName, "previous"),
                    ["installed_at_utc"] = installedAt
                }.ToJsonString());
            }
            using var app = await Start(settings: new()
            {
                ["Sli:Release:PackageRoot"] = root.FullName,
                ["CREDENTIALS_DIRECTORY"] = root.FullName
            });

            foreach (var (path, key) in new[]
            {
                ("/api/health/live", "runtime_identity"),
                ("/api/diagnostics/overview", "release_metadata"),
                ("/api/system/health", "release_metadata")
            })
            {
                using var response = await Request(app, "GET", path);
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                var release = (await Body(response))[key]!;
                Assert.Equal(receiptState == "missing" ? null : tag, (string?)release["release_tag"]);
                if (receiptState != "missing")
                    Assert.Equal(commit, (string?)release["git_commit"]);
                Assert.Equal(receiptState == "matching" ? installedAt : null, (string?)release["installed_at_utc"]);
            }
        }
        finally { root.Delete(recursive: true); }
    }

    [Theory]
    [InlineData("admin", "https://sli.example.test:9090/system/terminal", true)]
    [InlineData("admin", null, false)]
    [InlineData("admin", "http://sli.example.test:9090/system/terminal", false)]
    [InlineData("operator", "https://sli.example.test:9090/system/terminal", false)]
    public async Task Diagnostics_exposes_active_web_console_only_to_administrators(string role, string? url, bool visible)
    {
        using var app = await Start(role: role);
        if (url is not null) app.Files.CockpitStatus = new JsonObject { ["url"] = url };
        using var response = await Request(app, "GET", "/api/diagnostics/overview?run_checks=0");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var console = (await Body(response))["web_console"]!;
        Assert.Equal(visible, (bool)console["available"]!);
        Assert.Equal(visible ? url : null, (string?)console["url"]);
    }

    [Fact]
    public async Task Round2DetailedHealthRequiresCapabilityWithAuthenticationDisabled()
    {
        using var app = await Start(allow: false, settings: new() { ["Sli:AuthRequired"] = "false", ["Sli:AllowUnauthenticated"] = "true" });
        using var response = await Request(app, "GET", "/api/health/details");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var body = await Body(response);
        Assert.Equal("operations.view", (string?)body["required_capability"]); Assert.Equal(0, app.Queries.Reads);
    }

    [Theory] [MemberData(nameof(Routes))]
    public async Task EachRegisteredRouteHasTheSourceSuccessContract(string method, string path, int expected)
    {
        using var app = await Start(); using var response = await Request(app, method, path);
        if ((int)response.StatusCode != expected && method == "GET") await app.Service.ReadAsync(path, new(), TestContext.Current.CancellationToken);
        Assert.Equal(expected, (int)response.StatusCode); var body = await Body(response); Assert.NotEmpty(body);
        if (path.Contains("administrative-activity")) { Assert.Equal("administrative_activity_reader_runtime_disabled", (string?)body["error"]); Assert.Equal(0, app.Queries.Reads); }
        if (path.Contains("preflight")) { Assert.True((bool)body["valid"]!); Assert.Empty(body["network_actions"]!.AsArray()); Assert.Empty(body["database_actions"]!.AsArray()); Assert.Empty(body["collection_actions"]!.AsArray()); }
        if (path.EndsWith("overview") && !path.Contains("diagnostics")) { Assert.NotNull(body["collector_health"]); Assert.Equal("warn", (string?)body["storage"]?["status"]); Assert.Equal("not_registered", (string?)body["workers"]?["items"]?[0]?["state"]); }
        if (path.Contains("sources/DC1")) { Assert.Equal("not_collected", (string?)body["source"]?["disk_state"]); Assert.Equal("current", (string?)body["collection_freshness"]?["state"]); }
    }
    [Theory] [MemberData(nameof(Routes))]
    public async Task OperationalReadsRequireOperatorEvenWithCapability(string method, string path, int expected)
    {
        if (method != "GET") return;
        using var app = await Start(role: "viewer"); using var response = await Request(app, method, path);
        if (path is "/api/health/details" or "/api/v1/operations/sources/DC1")
            Assert.Equal(expected, (int)response.StatusCode);
        else
        {
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            var body = await Body(response); Assert.Single(body); Assert.Equal("insufficient_permissions", (string?)body["error"]);
            Assert.Equal(0, app.Queries.Reads);
        }
    }
    [Theory] [MemberData(nameof(Routes))]
    public async Task OperatorsReachOperationalReadHandlers(string method, string path, int expected)
    {
        if (method != "GET") return;
        using var app = await Start(role: "operator"); using var response = await Request(app, method, path);
        Assert.Equal(expected, (int)response.StatusCode);
    }
    [Theory] [MemberData(nameof(Routes))]
    public async Task EachRouteDeniesMissingCapabilityBeforeAnyOperationalRead(string method, string path, int _)
    {
        using var app = await Start(allow: false); using var response = await Request(app, method, path);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); var body = await Body(response); Assert.Equal("insufficient_capability", (string?)body["error"]);
        Assert.Equal(path.Contains("administrative-activity") ? "administrative.activity.view" : "operations.view", (string?)body["required_capability"]); Assert.Equal(0, app.Queries.Reads);
    }
    [Theory] [MemberData(nameof(Routes))]
    public async Task EachRouteRejectsUnauthenticatedRequests(string method, string path, int _)
    {
        using var app = await Start(authenticated: false); using var response = await Request(app, method, path);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode); Assert.Equal(0, app.Queries.Reads);
    }
    [Theory] [MemberData(nameof(Routes))]
    public async Task EachRouteKeepsItsReferenceInputRules(string method, string path, int expected)
    {
        using var app = await Start(); string target = path + "?ignored_input=untrusted&force=invalid&deep=invalid&connect=invalid&run_checks=invalid"; int status = expected;
        if (path == "/api/storage/lifecycle") { target = path + "?limit=invalid"; status = 400; }
        else if (path.Contains("administrative-activity")) { target = path + "?limit=invalid"; status = 400; }
        else if (path.Contains("sources/DC1")) { target = "/api/v1/operations/sources/" + new string('x', 256); status = 400; }
        else if (path == "/api/jobs/1") { target = "/api/jobs/invalid"; status = 400; }
        using var response = await Request(app, method, target, "[]");
        Assert.Equal(method == "POST" ? 400 : status, (int)response.StatusCode);
        if (method == "POST") Assert.Equal("json_object_required", (string?)(await Body(response))["error"]);
    }
    [Theory] [InlineData("operator")] [InlineData("viewer")]
    public async Task PreflightRetainsBothRoleGates(string role)
    { using var app = await Start(role: role, owner: true); using var response = await Request(app, "POST", "/api/v1/source-onboarding/preflight"); Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); Assert.Equal(0, app.Queries.Reads); }
    [Theory] [InlineData("deny", false)] [InlineData("allow", true)]
    public async Task ExplicitDenyAndResourceOnlyAllowCannotReadGlobalOperations(string effect, bool scoped)
    { using var app = await Start(effect: effect, scoped: scoped); using var response = await Request(app, "GET", "/api/v1/operations/overview"); Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); Assert.Equal(0, app.Queries.Reads); }
    [Fact]
    public async Task ReadinessOmitsRetiredCollectionSectionsAndKeepsUnknownMeasurements()
    {
        using var app = await Start(); using var response = await Request(app, "GET", "/api/v1/operations/overview?view=readiness"); var body = await Body(response);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); Assert.Null(body["collection"]); Assert.DoesNotContain(body["workers"]!["items"]!.AsArray(), r => (string?)r?["worker_name"] == "collection");
        Assert.Null(body["storage"]!["project_overview"]!["total_bytes"]); Assert.False((bool)body["storage"]!["project_overview"]!["complete"]!);
    }
    [Fact]
    public async Task OptionalFailureDoesNotBecomeAnEmptyHealthyResultOrExposeExceptionText()
    {
        using var app = await Start(); app.Queries.FailContaining = "runtime_worker_heartbeats";
        using var response = await Request(app, "GET", "/api/v1/operations/overview"); var body = await Body(response);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); Assert.Equal("unavailable", (string?)body["workers"]?["status"]); Assert.DoesNotContain("private-db", body.ToJsonString());
    }
    [Fact]
    public async Task SourceLookupIsCaseInsensitiveButAmbiguityIsNeverResolvedByRecency()
    {
        using var app = await Start(); app.Queries.Ambiguous = true;
        using var response = await Request(app, "GET", "/api/v1/operations/sources/dc1.");
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode); Assert.Equal("ambiguous_source_hostname", (string?)(await Body(response))["error"]);
    }
    [Fact]
    public async Task MissingJobAndSourceHaveTheReference404Codes()
    {
        using var app = await Start();
        foreach (var (path, error) in new[] { ("/api/jobs/999", "job_not_found"), ("/api/v1/operations/sources/absent", "source_not_found") })
        { using var response = await Request(app, "GET", path); Assert.Equal(HttpStatusCode.NotFound, response.StatusCode); Assert.Equal(error, (string?)(await Body(response))["error"]); }
    }
    [Fact]
    public async Task InvalidPreflightIsAReadOnlyPlanRatherThanAnHttpError()
    {
        using var app = await Start(); using var response = await Request(app, "POST", "/api/v1/source-onboarding/preflight", """{"hostname":"DC1","channels":[],"source_pack_id":"untrusted","adapter_id":"untrusted"}"""); var body = await Body(response);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); Assert.False((bool)body["valid"]!);
        Assert.Contains(body["issues"]!.AsArray(), i => (string?)i?["code"] == "duplicate_hostname"); Assert.Contains(body["issues"]!.AsArray(), i => (string?)i?["code"] == "unknown_source_pack");
    }
    [Fact]
    public async Task DcOnboardingPreflightReturnsTheReferencePlanWithoutSchedulingActions()
    {
        using var app = await Start();
        var jobsBefore = app.Jobs.List().ToJsonString();
        using var response = await Request(app, "POST", "/api/v1/source-onboarding/preflight",
            """{"hostname":"DC3","connect_address":"192.0.2.11","channels":["Security","System"]}""");
        var body = await Body(response);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True((bool)body["valid"]!);
        Assert.Equal("v1", (string?)body["api_version"]);
        Assert.Equal("dc_onboarding_preflight", (string?)body["kind"]);
        Assert.Equal("DC3", (string?)body["hostname"]);
        Assert.Equal("192.0.2.11", (string?)body["connect_address"]);
        Assert.Equal("sli.windows.ad-dc", (string?)body["source_pack_id"]);
        Assert.Equal("windows-eventlog-pywin32", (string?)body["adapter_id"]);
        Assert.Equal(new[] { "Security", "System" }, body["channels"]!.AsArray().Select(c => (string?)c));
        Assert.Empty(body["issues"]!.AsArray());
        Assert.Empty(body["network_actions"]!.AsArray());
        Assert.Empty(body["database_actions"]!.AsArray());
        Assert.Empty(body["collection_actions"]!.AsArray());
        Assert.Equal(jobsBefore, app.Jobs.List().ToJsonString());
        var read = Assert.Single(app.Queries.Calls);
        Assert.StartsWith("select hostname,connect_address,", read.Sql);
        Assert.Contains("from domain_controller_targets", read.Sql);
        Assert.Empty(read.Parameters);
    }
    [Theory]
    [InlineData("DC1")]
    [InlineData("dc1")]
    public async Task DcOnboardingPreflightReportsAllReferenceValidationErrors(string hostname)
    {
        using var app = await Start();
        var candidate = new JsonObject { ["hostname"] = hostname, ["connect_address"] = "https://dc1.example.test",
            ["channels"] = new JsonArray("Security", "Untrusted/Other"), ["adapter_id"] = "made-up-adapter" };
        using var response = await Request(app, "POST", "/api/v1/source-onboarding/preflight", candidate.ToJsonString());
        var body = await Body(response);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False((bool)body["valid"]!);
        Assert.Equal(new[] { "duplicate_hostname", "invalid_connect_address", "unknown_adapter", "unsupported_adapter", "unsupported_channel" },
            body["issues"]!.AsArray().Select(i => (string?)i?["code"]).Order(StringComparer.Ordinal));
    }
    [Fact]
    public async Task DcOnboardingPreflightRequiresExplicitChannelsEvenForAValidController()
    {
        using var app = await Start();
        using var response = await Request(app, "POST", "/api/v1/source-onboarding/preflight",
            """{"hostname":"DC3","connect_address":"dc3.example.test"}""");
        var body = await Body(response);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False((bool)body["valid"]!);
        Assert.Equal("missing_channels", (string?)Assert.Single(body["issues"]!.AsArray())?["code"]);
    }
    [Fact]
    public async Task PreflightRejectsCrossOriginBeforeBodyAndDataAccess()
    {
        using var app = await Start(); app.Client.DefaultRequestHeaders.Add("Origin", "https://attacker.invalid"); using var response = await Request(app, "POST", "/api/v1/source-onboarding/preflight");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); Assert.Equal("cross_origin_request_rejected", (string?)(await Body(response))["error"]); Assert.Equal(0, app.Queries.Reads);
    }
}
