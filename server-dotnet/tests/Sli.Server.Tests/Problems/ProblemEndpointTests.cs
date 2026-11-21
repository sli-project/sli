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
using Sli.Server.Problems;
using Xunit;

namespace Sli.Server.Tests.Problems;

public sealed class ProblemEndpointTests
{
    internal const string Uuid = "00000000-0000-4000-8000-000000000001";
    internal const string WatchBody = """{"entity_id":12,"owner":"fixture","reason":"reason","active":true,"revision":0,"expires_at":"2099-01-01T00:00:00Z"}""";
    internal const string DecoyBody = """{"kind":"account","identity":{"domain_id":1,"entity_id":12,"sid":"S-1-5-21-100000001-200000002-300000003-1001","guid":"00000000-0000-4000-8000-000000000001"},"owner":"fixture","reason":"reason","active":true,"revision":0}""";
    internal static JsonElement J(object value) => JsonSerializer.SerializeToElement(value);
    internal static AccessFacts Facts(bool allowed = true)
    {
        string[] caps = ["investigations.view", "investigations.manage", "watch.manage", "decoys.manage", "objects.view", "field.security", "field.identity_basic", "field.technical", "field.raw_evidence", "evidence.exact"];
        string[] fields = ["security", "identity_basic", "technical", "raw_evidence"];
        var reports = new[] { "security.queue", "watch.registry", "decoys.registry" };
        string[] actions = ["view", "manage_watch", "manage_decoy"];
        return new(false, "admin", [], [], allowed ? caps.Select(c => J(new { capability_key = c, effect = "allow", scope_json = new { kind = "all" } })).ToArray() : [], [], [],
            allowed ? reports.Select(r => J(new { report_key = r, effect = "allow", allowed_actions = actions, field_categories = fields, scope_json = new { kind = "all" } })).ToArray() : [],
            reports.Select(r => J(new { report_key = r, version = 1, dataset_version = 1, definition_json = new { actions }, actions_json = actions, fields_json = fields.Select(c => new { category = c }) })).ToArray());
    }
    internal sealed class Authentication : IPrincipalAuthenticator
    {
        public string Role = "admin"; public bool LoggedIn = true; public string? Username = "alice";
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext c, CancellationToken ct) => ValueTask.FromResult(LoggedIn ? AuthenticationResult.Success(new("session", 1, Role, Username)) : AuthenticationResult.Denied(401, "authentication_required"));
    }
    internal sealed class FactsReader(bool allowed, AccessFacts? facts = null) : IAccessFactsRepository { public Task<AccessFacts> LoadAsync(Principal p, CancellationToken ct) => Task.FromResult(facts ?? Facts(allowed)); }
    internal sealed class Repository : IProblemRepository
    {
        public Task<JsonObject> LegacyFindingsAsync(string query, int limit, CancellationToken ct) => Result("""{"items":[],"summary":[],"backend":"postgres"}""");
        public int Calls; public string? Error; public Exception? Failure; public int ErrorStatus = 409; public FindingStatusInput? Status; public RiskInput? Risk;
        public FindingQuery? Query; public (long Finding, long? Before)? AuditRequest;
        public (long[] Ids, string Actor)? BulkRequest;
        public FindingQuery? FindingsQuery => Query;
        Task<JsonObject> Result(string json = "{}") { Calls++; if (Failure is not null) throw Failure; if (Error is not null) throw new ProblemException(Error, ErrorStatus); return Task.FromResult(JsonNode.Parse(json)!.AsObject()); }
        public Task<JsonObject> FindingsAsync(FindingQuery q, ProblemAccess a, CancellationToken ct) { Query = q; return Result("""{"items":[{"id":7,"rule_code":"semantic.security.audit_controls_changed","presentation_facts":{"computer":"dc1.example.test"},"title":"Audit policy was changed","status":"new","severity":"high","evidence_count":0,"evidence":[],"entities":[],"status_history":[],"risk_audit":[]}],"summary":[],"has_more":false}"""); }
        public Task<JsonObject> StatusAsync(long id, FindingStatusInput input, string actor, CancellationToken ct) { Status = input; return Result("""{"status":"ok","backend":"postgres","changed":true,"finding":{"id":7,"status":"active","status_history":[]}}"""); }
        public Task<JsonObject> BulkStatusAsync(long[] ids, FindingStatusInput input, string actor, ProblemAccess access, CancellationToken ct)
        {
            BulkRequest = (ids, actor); Status = input;
            return Result("""{"status":"ok","changed":2}""");
        }
        public Task<JsonObject> RiskAsync(long id, RiskInput input, CancellationToken ct) { Risk = input; return Result("""{"status":"ok","acceptance":{"id":8},"risk_audit":[]}"""); }
        public Task<JsonObject> ResponsiblesAsync(CancellationToken ct) => Result("""{"items":[{"id":1,"username":"alice"}]}""");
        public Task<JsonObject> RiskAuditAsync(long id, long? before, CancellationToken ct) { AuditRequest = (id, before); return Result("""{"items":[],"has_more":false}"""); }
        public Task<JsonObject> WatchListAsync(RegistryQuery q, ProblemAccess a, Principal p, CancellationToken ct) => Result("""{"items":[],"has_more":false,"next_cursor":null,"can_manage":false}""");
        public Task<JsonObject> WatchSaveAsync(string? id, WatchInput input, ProblemAccess a, Principal p, CancellationToken ct) => Result("""{"item":{"id":"00000000-0000-4000-8000-000000000001","revision":1}}""");
        public Task<JsonObject> DecoyListAsync(RegistryQuery q, ProblemAccess a, Principal p, CancellationToken ct) => Result("""{"items":[],"has_more":false,"next_cursor":null}""");
        public Task<JsonObject> DecoySaveAsync(string? id, DecoyInput input, ProblemAccess a, Principal p, CancellationToken ct) => Result("""{"item":{"id":"00000000-0000-4000-8000-000000000001","revision":1,"readiness":{"state":"not_ready"}}}""");
    }
    internal sealed class Fixture : IAsyncDisposable
    {
        public readonly Repository Repo = new(); public readonly Authentication Auth = new();
        public HttpClient Client = null!; IHost host = null!;
        public static async Task<Fixture> Start(bool allowed = true, AccessFacts? facts = null, TimeProvider? clock = null, IProblemRepository? repository = null)
        {
            var f = new Fixture(); var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:AuthRequired"] = "true" }).Build();
            f.host = await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(s => {
                s.AddRouting(); s.AddLogging(); s.AddSingleton<IConfiguration>(config); s.AddSingleton(new AuthRequestPolicy(config)); s.AddSingleton(new TransportGate(config));
                s.AddSingleton<IPrincipalAuthenticator>(f.Auth); s.AddSingleton<IAccessFactsRepository>(new FactsReader(allowed, facts)); s.AddSingleton<IProblemRepository>(repository ?? f.Repo); s.AddSingleton(clock ?? TimeProvider.System);
            }).Configure(app => { app.UseRouting(); app.UseEndpoints(e => e.MapProblemLifecycle()); })).StartAsync(TestContext.Current.CancellationToken);
            f.Client = f.host.GetTestClient(); f.Client.BaseAddress = new("https://localhost"); f.Client.DefaultRequestHeaders.AcceptLanguage.ParseAdd("en"); return f;
        }
        public async Task<(int Status, JsonObject Json)> Send(string method, string path, string? body)
        {
            using var request = new HttpRequestMessage(new HttpMethod(method), path); if (body is not null) request.Content = new StringContent(body, Encoding.UTF8, "application/json");
            using var response = await Client.SendAsync(request, TestContext.Current.CancellationToken);
            return ((int)response.StatusCode, response.StatusCode == HttpStatusCode.Found ? new JsonObject() : JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject());
        }
        public ValueTask DisposeAsync() { Client.Dispose(); host.Dispose(); return ValueTask.CompletedTask; }
    }
    public static IEnumerable<object[]> Routes()
    {
        yield return ["GET", "/api/findings?source=semantic-production", "", 200];
        yield return ["GET", "/api/findings/risk-responsibles", "", 200];
        yield return ["GET", "/api/findings/7/risk-audit?before=99", "", 200];
        yield return ["GET", "/reports/findings.html", "", 302];
        yield return ["POST", "/api/findings/7/status", """{"status":"active","note":"reason"}""", 200];
        yield return ["POST", "/api/findings/bulk-status", """{"ids":[9,7],"status":"closed"}""", 200];
        yield return ["POST", "/api/findings/7/risk-acceptance", """{"action":"revoke","id":8}""", 200];
        yield return ["GET", "/api/v1/watch?entity_id=12", "", 200];
        yield return ["POST", "/api/v1/watch", WatchBody, 200];
        yield return ["POST", "/api/v1/watch/" + Uuid, WatchBody, 200];
        yield return ["GET", "/api/v1/decoys", "", 200];
        yield return ["POST", "/api/v1/decoys", DecoyBody, 200];
        yield return ["POST", "/api/v1/decoys/" + Uuid, DecoyBody, 200];
    }
    [Theory, MemberData(nameof(Routes))]
    public async Task EveryRouteIsRegisteredAndReturnsSourceShape(string method, string path, string body, int expected)
    {
        await using var f = await Fixture.Start(); var (status, json) = await f.Send(method, path, body.Length > 0 ? body : null);
        Assert.Equal(expected, status); Assert.Equal(expected == 302 ? 0 : 1, f.Repo.Calls);
        if (path == "/api/findings?source=semantic-production") { Assert.Equal("security.problems.presentation.audit_title", json["items"]![0]!["title_code"]!.GetValue<string>()); Assert.Equal("New", json["items"]![0]!["status_message"]!["text"]!.GetValue<string>()); }
        else if (path == "/reports/findings.html") Assert.Empty(json);
        else if (method == "POST" && path.Contains("/api/v1/")) Assert.Equal(1, json["item"]!["revision"]!.GetValue<int>());
        else if (method == "POST") Assert.Equal("ok", json["status"]!.GetValue<string>());
        else Assert.IsType<JsonArray>(json["items"]);
    }
    [Theory, MemberData(nameof(Routes))]
    public async Task EveryRoutePreventsUnauthenticatedRepositoryReads(string method, string path, string body, int ignored)
    {
        Assert.Contains(ignored, new[] { 200, 302 });
        await using var f = await Fixture.Start(); f.Auth.LoggedIn = false; var response = await f.Send(method, path, body.Length > 0 ? body : null);
        Assert.Equal(path == "/reports/findings.html" ? 302 : 401, response.Status); Assert.Equal(0, f.Repo.Calls);
    }
    [Theory, MemberData(nameof(Routes))]
    public async Task EveryProtectedRouteDeniesMissingGrantsBeforeBody(string method, string path, string body, int ignored)
    {
        Assert.Contains(ignored, new[] { 200, 302 }); Assert.NotNull(body);
        await using var f = await Fixture.Start(false); var response = await f.Send(method, path, method == "POST" ? "invalid JSON" : null);
        // The legacy bookmark redirects without a report grant in the reference.
        Assert.Equal(path == "/reports/findings.html" ? 302 : 403, response.Status); Assert.Equal(0, f.Repo.Calls);
    }
    [Theory]
    [InlineData("GET", "/api/findings?source=semantic-production&domain=oops", null, "report_request_invalid")]
    [InlineData("GET", "/api/findings/no/risk-audit", null, "invalid_cursor_or_finding")]
    [InlineData("GET", "/api/findings/7/risk-audit?before=0", null, "invalid_cursor_or_finding")]
    [InlineData("POST", "/api/findings/no/status", "{}", "invalid_finding_id")]
    [InlineData("POST", "/api/findings/bulk-status", "{\"ids\":[0],\"status\":\"closed\"}", "invalid_finding_id")]
    [InlineData("POST", "/api/findings/bulk-status", "{\"ids\":[7],\"status\":\"confirmed\"}", "invalid_bulk_status")]
    [InlineData("POST", "/api/findings/7/status", "{}", "invalid_status")]
    [InlineData("POST", "/api/findings/no/risk-acceptance", "{}", "invalid_finding_id")]
    [InlineData("POST", "/api/findings/7/risk-acceptance", "{}", "invalid_action")]
    [InlineData("GET", "/api/v1/watch?entity_id=oops", null, "watch_invalid")]
    [InlineData("GET", "/api/v1/watch?cursor=oops", null, "watch_invalid")]
    [InlineData("POST", "/api/v1/watch", "{}", "watch_invalid")]
    [InlineData("POST", "/api/v1/watch/00000000-0000-4000-8000-000000000001", "{}", "watch_invalid")]
    [InlineData("GET", "/api/v1/decoys?revision=1", null, "decoy_invalid")]
    [InlineData("GET", "/api/v1/decoys?cursor=oops", null, "decoy_invalid")]
    [InlineData("POST", "/api/v1/decoys", "{}", "decoy_invalid")]
    [InlineData("POST", "/api/v1/decoys/00000000-0000-4000-8000-000000000001", "{}", "decoy_invalid")]
    public async Task InvalidInputNeverReachesRepository(string method, string path, string? body, string error)
    {
        await using var f = await Fixture.Start(); var response = await f.Send(method, path, body);
        Assert.Equal(400, response.Status); Assert.Equal(error, response.Json["error"]!.GetValue<string>()); Assert.Equal(0, f.Repo.Calls);
        if (path.Contains("/api/v1/")) Assert.NotNull(response.Json["message"]?["text"]);
    }
    [Fact]
    public async Task BulkReopenUsesAuthenticatedActorAndDistinctIds()
    {
        await using var f = await Fixture.Start();
        var result = await f.Send("POST", "/api/findings/bulk-status", """{"ids":[9,7,9],"status":"active"}""");
        Assert.Equal(200, result.Status);
        Assert.Equal(new long[] { 7, 9 }, f.Repo.BulkRequest?.Ids);
        Assert.Equal("alice", f.Repo.BulkRequest?.Actor);
        Assert.Equal("active", f.Repo.Status?.Status);
        Assert.NotEmpty(f.Repo.Status?.Reason ?? "");
    }
    [Theory]
    [InlineData("/api/findings/risk-responsibles?before=invalid", 200)]
    [InlineData("/reports/findings.html?limit=invalid", 302)]
    [InlineData("/api/findings?source=legacy", 410)]
    [InlineData("/api/findings", 410)]
    [InlineData("/api/findings?source=semantic-production&source=semantic-production", 410)]
    public async Task InputlessAndRetiredRoutesKeepReferenceBehavior(string path, int expected)
    { await using var f = await Fixture.Start(); Assert.Equal(expected, (await f.Send("GET", path, null)).Status); }

    [Theory]
    [InlineData("/reports/findings.html", "/app/scenarios")]
    [InlineData("/reports/findings.html?legacy=1&limit=invalid", "/app/scenarios")]
    [InlineData("/reports/findings.html?legacy=1&q=a%26b&unknown=value", "/app/scenarios?q=a%26b")]
    public async Task LegacyFindingsBookmarkAlwaysRedirectsToScenarioVerdictOwner(string path, string target)
    {
        await using var f = await Fixture.Start(false);
        using var response = await f.Client.GetAsync(path, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal(target, response.Headers.Location!.OriginalString);
        Assert.Equal(0, f.Repo.Calls);
    }
    [Fact] public async Task TouchesUsesExistingDecoyRouteAndValidatesExactVersion()
    {
        await using var f = await Fixture.Start(); Assert.Equal(200, (await f.Send("GET", "/api/v1/decoys?touches=" + Uuid + "&revision=1", null)).Status);
        Assert.Equal(400, (await f.Send("GET", "/api/v1/decoys?touches=" + Uuid + "&revision=1&cursor=no", null)).Status); Assert.Equal(1, f.Repo.Calls);
    }
    [Theory]
    [InlineData("/api/v1/watch", WatchBody)]
    [InlineData("/api/v1/decoys", DecoyBody)]
    [InlineData("/api/findings/7/status", "{\"status\":\"active\",\"note\":\"reason\"}")]
    [InlineData("/api/findings/7/risk-acceptance", "{\"action\":\"revoke\",\"id\":8}")]
    public async Task CrossOriginMutationHasNoRepositoryCalls(string path, string body)
    {
        await using var f = await Fixture.Start(); f.Client.DefaultRequestHeaders.Add("Origin", "https://untrusted.invalid");
        Assert.Equal(403, (await f.Send("POST", path, body)).Status); Assert.Equal(0, f.Repo.Calls);
    }
    [Theory]
    [InlineData("/api/v1/watch", WatchBody, "viewer")]
    [InlineData("/api/v1/decoys", DecoyBody, "operator")]
    [InlineData("/api/findings/7/status", "{}", "viewer")]
    [InlineData("/api/findings/7/risk-acceptance", "{}", "viewer")]
    public async Task MutationCoarseRolesCannotBeBypassedByGrants(string path, string body, string role)
    { await using var f = await Fixture.Start(); f.Auth.Role = role; Assert.Equal(403, (await f.Send("POST", path, body)).Status); Assert.Equal(0, f.Repo.Calls); }
    [Theory]
    [InlineData("/api/findings/7/status", "{\"status\":\"active\",\"note\":\"reason\"}", "invalid_transition", 409)]
    [InlineData("/api/findings/7/status", "{\"status\":\"active\",\"note\":\"reason\"}", "not_found", 404)]
    [InlineData("/api/findings/7/risk-acceptance", "{\"action\":\"revoke\",\"id\":8}", "risk_not_active", 409)]
    [InlineData("/api/v1/watch", WatchBody, "watch_revision_conflict", 409)]
    [InlineData("/api/v1/decoys", DecoyBody, "decoy_duplicate", 409)]
    public async Task RepositoryErrorsKeepSourceStatusAndCode(string path, string body, string error, int expected)
    {
        await using var f = await Fixture.Start(); f.Repo.Error = error; f.Repo.ErrorStatus = expected;
        var response = await f.Send("POST", path, body); Assert.Equal(expected, response.Status); Assert.Equal(error, response.Json["error"]!.GetValue<string>());
    }
    [Theory]
    [InlineData("/api/v1/watch", "watch_revision_conflict", "watch_unavailable")]
    [InlineData("/api/v1/decoys", "decoy_duplicate", "decoy_unavailable")]
    public async Task DatabaseConflictsAndOutagesRemainDistinctAndDoNotLeakDetails(string path, string conflict, string unavailable)
    {
        await using var f = await Fixture.Start(); f.Repo.Failure = new Npgsql.PostgresException("private source row", "ERROR", "ERROR", "23505");
        var response = await f.Send("GET", path, null); Assert.Equal(409, response.Status); Assert.Equal(conflict, response.Json["error"]!.GetValue<string>());
        f.Repo.Failure = new InvalidOperationException("private source row"); response = await f.Send("GET", path, null);
        Assert.Equal(503, response.Status); Assert.Equal(unavailable, response.Json["error"]!.GetValue<string>()); Assert.DoesNotContain("private source row", response.Json.ToJsonString());
    }
    [Theory]
    [InlineData("/api/v1/watch", "watch_invalid")]
    [InlineData("/api/v1/decoys", "decoy_invalid")]
    [InlineData("/api/findings/7/status", "invalid_json")]
    [InlineData("/api/findings/7/risk-acceptance", "invalid_json")]
    public async Task MalformedJsonKeepsTheRouteInputError(string path, string error)
    {
        await using var f = await Fixture.Start(); var response = await f.Send("POST", path, "{");
        Assert.Equal(400, response.Status); Assert.Equal(error, response.Json["error"]!.GetValue<string>()); Assert.Equal(0, f.Repo.Calls);
    }
    [Fact] public async Task CreateRiskAcceptancePassesVerifiedActorAndBoundedExpiry()
    {
        await using var f = await Fixture.Start(); var body = new JsonObject { ["action"] = "create", ["reason"] = "fixture reason", ["responsible_user_id"] = 1L, ["expires_at"] = DateTimeOffset.UtcNow.AddDays(7).ToString("O") };
        Assert.Equal(200, (await f.Send("POST", "/api/findings/7/risk-acceptance", body.ToJsonString())).Status);
        Assert.Equal("alice", f.Repo.Risk!.Actor); Assert.Equal(1L, f.Repo.Risk.Responsible);
    }
}
