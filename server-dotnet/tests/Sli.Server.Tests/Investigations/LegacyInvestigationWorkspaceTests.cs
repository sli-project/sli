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
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Compatibility;
using Sli.Server.Problems;
using Sli.Server.Workspace;
using Xunit;

namespace Sli.Server.Tests.Investigations;

public sealed class LegacyInvestigationWorkspaceTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static void Match(JsonNode? expected, JsonNode? actual, string path)
    {
        if (expected is JsonObject obj && actual is JsonObject other)
        {
            Assert.Equal(obj.Select(p => p.Key).Order(), other.Select(p => p.Key).Order());
            foreach (var (key, value) in obj) Match(value, other[key], path + "." + key);
        }
        else if (expected is JsonArray array && actual is JsonArray values)
        {
            Assert.Equal(array.Count, values.Count);
            for (int i = 0; i < array.Count; i++) Match(array[i], values[i], path + "[" + i + "]");
        }
        else Assert.True(JsonNode.DeepEquals(expected, actual), path + ": expected " + expected?.ToJsonString() + "; actual " + actual?.ToJsonString());
    }
    public static IEnumerable<object[]> Vectors()
    {
        using var stream = typeof(LegacyInvestigationWorkspaceTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Investigations.Fixtures.workspace-source.json")!;
        return JsonNode.Parse(stream)!.AsArray().Select(v => new object[] { v!["name"]!.ToString(), v.ToJsonString() }).ToArray();
    }
    sealed class Events(JsonObject response) : ILegacyHttpReader
    {
        public int Calls; public LegacyQuery? Input; public Exception? Failure;
        public Task<JsonObject> ReadAsync(string path, LegacyQuery query, CancellationToken ct)
        {
            Assert.Equal("/api/events/search", path); Calls++; Input = query;
            if (Failure is not null) throw Failure;
            return Task.FromResult(response.DeepClone().AsObject());
        }
    }
    sealed class Findings(JsonObject response) : IProblemRepository
    {
        public int Calls; public string? Query;
        public Task<JsonObject> LegacyFindingsAsync(string query, int limit, CancellationToken ct)
        { Calls++; Query = query; Assert.Equal(50, limit); return Task.FromResult(response.DeepClone().AsObject()); }
        public Task<JsonObject> FindingsAsync(FindingQuery q, ProblemAccess a, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> StatusAsync(long id, FindingStatusInput i, string a, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> RiskAsync(long id, RiskInput i, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> ResponsiblesAsync(CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> RiskAuditAsync(long id, long? before, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> WatchListAsync(RegistryQuery q, ProblemAccess a, Principal p, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> WatchSaveAsync(string? id, WatchInput i, ProblemAccess a, Principal p, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> DecoyListAsync(RegistryQuery q, ProblemAccess a, Principal p, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> DecoySaveAsync(string? id, DecoyInput i, ProblemAccess a, Principal p, CancellationToken ct) => throw new NotSupportedException();
    }
    sealed class Auth(bool loggedIn, string role) : IPrincipalAuthenticator
    {
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext c, CancellationToken ct) => ValueTask.FromResult(loggedIn
            ? AuthenticationResult.Success(new("session", 1, role)) : AuthenticationResult.Denied(401, "authentication_required"));
    }
    sealed class Facts(string grant) : IAccessFactsRepository
    {
        public Task<AccessFacts> LoadAsync(Principal p, CancellationToken ct) => Task.FromResult(new AccessFacts(false, p.Role, [], [],
            grant == "none" ? [] : [JsonSerializer.SerializeToElement(new { capability_key = "investigations.view", effect = "allow", scope_json = grant == "all" ? (object)new { kind = grant } : new { kind = grant, ids = new[] { 1 } } })], [], [], [], []));
    }
    static Task<IHost> Start(Events events, Findings findings, string grant = "all", bool loggedIn = true, string role = "viewer")
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:AuthRequired"] = "true" }).Build();
        return new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(s => {
            s.AddRouting(); s.AddLogging(); s.AddSingleton<IConfiguration>(config); s.AddSingleton(new AuthRequestPolicy(config)); s.AddSingleton(new TransportGate(config));
            s.AddSingleton<IPrincipalAuthenticator>(new Auth(loggedIn, role)); s.AddSingleton<IAccessFactsRepository>(new Facts(grant));
            s.AddSingleton<ILegacyHttpReader>(events); s.AddSingleton<IProblemRepository>(findings); s.AddSingleton<LegacyInvestigationReader>();
            s.AddSingleton<IWorkspaceCompatibilityReader>(p => new WorkspaceCompatibilityReader(null!, config, null!, null!, p.GetRequiredService<LegacyInvestigationReader>()));
        }).Configure(app => { app.UseRouting(); app.UseEndpoints(e => e.MapWorkspaceCompatibility()); })).StartAsync(Ct);
    }
    [Theory, MemberData(nameof(Vectors))]
    public async Task GetMatchesExecutedPythonReference(string name, string json)
    {
        var vector = JsonNode.Parse(json)!;
        var events = new Events(vector["search"]!.AsObject()); var findings = new Findings(vector["findings"]!.AsObject());
        using var host = await Start(events, findings); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/investigation/workspace?" + vector["query"], Ct);
        Assert.Equal(vector["status"]!.GetValue<int>(), (int)response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType!.MediaType);
        var actual = JsonNode.Parse(await response.Content.ReadAsStringAsync(Ct))!.AsObject();
        if (response.StatusCode == HttpStatusCode.InternalServerError)
        { Assert.True(Guid.TryParse(actual["internal_error_id"]?.ToString(), out _)); actual.Remove("internal_error_id"); }
        Match(vector["body"], actual, name);
        bool searched = vector["calls"]?["normalized"] is not null;
        Assert.Equal(searched ? 1 : 0, events.Calls); Assert.Equal(searched ? 1 : 0, findings.Calls);
        if (!searched) return;
        var normalized = vector["calls"]!["normalized"]!;
        foreach (string key in new[] { "q", "limit", "order", "time_from", "time_to", "timezone", "event_ids" })
            Assert.True(JsonNode.DeepEquals(normalized[key], events.Input!.Filters[key]), name + ": search " + key);
        Assert.True(events.Input!.Filters["include_internal_evidence"]!.GetValue<bool>());
        Assert.Equal(vector["calls"]!["findings"]!["q"]!.ToString(), findings.Query);
    }
    [Theory]
    [InlineData("none", true, "viewer", 403)]
    [InlineData("domain", true, "viewer", 403)]
    [InlineData("all", false, "viewer", 401)]
    [InlineData("all", true, "unknown", 403)]
    public async Task RightsPrecedeInputAndDataReads(string grant, bool loggedIn, string role, int status)
    {
        var events = new Events(new()); var findings = new Findings(new());
        using var host = await Start(events, findings, grant, loggedIn, role); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/investigation/workspace?q=fixture&limit=bad", Ct);
        Assert.Equal(status, (int)response.StatusCode); Assert.Equal(0, events.Calls); Assert.Equal(0, findings.Calls);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(Ct))!;
        Assert.Equal(status == 401 ? "authentication_required" : role == "unknown" ? "insufficient_permissions" : grant == "domain" ? "resource_context_required" : "insufficient_capability", body["error"]!.ToString());
        if (status == 403 && role != "unknown") Assert.Equal("investigations.view", body["required_capability"]!.ToString());
    }
    [Theory]
    [InlineData(409, "storage_transition_authorization_invalid")]
    [InlineData(503, "report_read_timeout")]
    [InlineData(500, "internal_server_error")]
    public async Task ReadFailuresUseSourceStatusAndDoNotExposeExceptionDetails(int status, string error)
    {
        var events = new Events(new()) { Failure = status switch {
            409 => new LegacyInputException(error, 409),
            503 => new PostgresException("private fixture detail", "ERROR", "ERROR", "57014"),
            _ => new InvalidOperationException("private fixture detail")
        } };
        var findings = new Findings(new()); using var host = await Start(events, findings); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/investigation/workspace?q=fixture", Ct);
        string body = await response.Content.ReadAsStringAsync(Ct);
        Assert.Equal(status, (int)response.StatusCode); Assert.Equal(error, JsonNode.Parse(body)!["error"]!.ToString());
        Assert.DoesNotContain("private fixture detail", body); Assert.Equal(0, findings.Calls);
        if (status == 503) Assert.Equal("unavailable", JsonNode.Parse(body)!["state"]!.ToString());
    }
}
