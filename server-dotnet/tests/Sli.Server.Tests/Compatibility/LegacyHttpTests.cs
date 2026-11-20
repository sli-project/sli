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
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Compatibility;
using Sli.Server.Hosting;
using Xunit;

namespace Sli.Server.Tests.Compatibility;

public sealed class LegacyHttpTests
{
    [Fact]
    public void RouteParityManifestAcceptsReactAndRemovesAllLegacyFallbacks()
    {
        var manifest = Sli.Server.Workspace.LegacyWorkspaceModels.Parity();
        Assert.Equal("accepted", manifest["status"]!.GetValue<string>());
        Assert.Equal("removed", manifest["legacy_fallback"]!.GetValue<string>());
        Assert.NotEmpty(manifest["mapped_routes"]!.AsArray());
        Assert.All(manifest["mapped_routes"]!.AsArray(), item => Assert.Null(item!["fallback"]));
        Assert.Contains(manifest["export_only_routes"]!.AsArray(), item => item!.GetValue<string>() == "/reports/ai-reports.html");
    }

    [Theory]
    [InlineData("/reports/collector-health.html", "/app/operations")]
    [InlineData("/reports/autocollection.html", "/app/operations")]
    [InlineData("/reports/diagnostics.html", "/app/operations")]
    [InlineData("/reports/storage-health.html", "/app/operations")]
    [InlineData("/reports/system-health.html", "/app/operations")]
    [InlineData("/reports/investigation.html", "/app/investigations")]
    [InlineData("/reports/role-overview.html", "/app/settings")]
    [InlineData("/reports/ui-navigation.html", "/app/settings")]
    public void RemainingReportBookmarksRedirectAndPreserveOnlyReferenceQuery(string path, string target)
    {
        var query = new QueryCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues> { ["q"] = "a & b", ["limit"] = "bad" });
        Assert.Equal(target + "?q=a+%26+b", LegacyHttpEndpoints.Redirect(path, query));
        Assert.NotNull(LegacyHttpEndpoints.Capability(path));
    }
    sealed class Authentication(bool authenticated, string role) : IPrincipalAuthenticator
    {
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext c, CancellationToken ct) => ValueTask.FromResult(authenticated ? AuthenticationResult.Success(new("session", 1, role)) : AuthenticationResult.Denied(401, "authentication_required"));
    }
    sealed class Facts(bool allowed, bool scoped) : IAccessFactsRepository
    {
        public Task<AccessFacts> LoadAsync(Principal p, CancellationToken ct) => Task.FromResult(new AccessFacts(false, p.Role, [], [], allowed ?
            new[] { "events.view", "evidence.exact", "objects.view", "semantic.review", "operations.view" }.Select(key => JsonSerializer.SerializeToElement(new { capability_key = key, effect = "allow", scope_json = scoped ? (object)new { kind = "domain", ids = new[] { 7 } } : new { kind = "all" } })).ToArray() : [], [], [], [], []));
    }
    sealed class Reader : ILegacyHttpReader
    {
        public int Calls;
        public Exception? Error;
        public Task<JsonObject> ReadAsync(string path, LegacyQuery query, CancellationToken ct)
        {
            Calls++; if (Error is {} error) throw error;
            return Task.FromResult(new JsonObject { ["route"] = path, ["filters"] = query.Filters.DeepClone(), ["items"] = new JsonArray(), ["run"] = null, ["matched_total"] = 0, ["returned_count"] = 0, ["truncated"] = false,
                ["model"] = "gpt-5.5", ["prompt_text"] = "<script>fixture</script>", ["response_schema"] = AiPreviewRedaction.Resource["schema"]!.DeepClone() });
        }
    }
    static async Task<IHost> Host(ILegacyHttpReader reader, bool allowed = true, bool authenticated = true, bool scoped = false, string role = "operator")
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:AuthRequired"] = "true" }).Build();
        return await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(services =>
        {
            services.AddRouting(); services.AddLogging(); services.AddSingleton<IConfiguration>(config);
            services.AddSingleton(new AuthRequestPolicy(config)); services.AddSingleton(new TransportGate(config));
            services.AddSingleton<IPrincipalAuthenticator>(new Authentication(authenticated, role));
            services.AddSingleton<IAccessFactsRepository>(new Facts(allowed, scoped)); services.AddSingleton<ILegacyHttpReader>(reader);
        }).Configure(app => { app.UseRouting(); app.UseEndpoints(routes => { routes.MapLegacyHttp(); routes.MapSliStaticAssets(); }); })).StartAsync(TestContext.Current.CancellationToken);
    }
    [Theory]
    [InlineData("/api/events/search")]
    [InlineData("/api/ai/prompt-preview")]
    [InlineData("/reports/ai-reports.html")]
    public async Task Retired_routes_return_disabled_after_access_checks_without_a_store(string path)
    {
        var reader = new LegacyHttpReader(null!, Microsoft.Extensions.Logging.Abstractions.NullLogger<LegacyHttpReader>.Instance);
        using var host = await Host(reader); using var client = host.GetTestClient();
        using var response = await client.GetAsync(path, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("module_disabled", JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!["error"]!.ToString());
    }

    public static TheoryData<string, int> Routes => new()
    {
        { "/api/events/details?event_db_id=7", 200 }, { "/api/events/search", 200 }, { "/api/events/search/deep?q=test", 200 },
        { "/api/events/summary", 200 }, { "/api/events/timeline?q=test", 200 }, { "/api/entities/details?entity_id=7", 200 }, { "/api/entities/summary", 200 },
        { "/api/ai/prompt-preview", 200 }, { "/api/ai/redaction-preview", 200 }, { "/api/ai/runs", 200 },
        { "/api/security/events-monitor", 200 }, { "/reports/security-events-monitor.csv", 200 }, { "/reports/security-events-monitor.html", 302 },
        { "/reports/ai-analysis.html", 200 }, { "/reports/ai-reports.html", 200 }, { "/reports/ai-prompt-preview.html", 200 }, { "/reports/ai-redaction-preview.html", 200 },
        { "/reports/domain-security-overview.html", 403 }, { "/reports/search.html", 302 }, { "/reports/search-deep.html", 302 },
        { "/reports/event-details.html?event_db_id=7", 302 }, { "/reports/entity-details.html?entity_id=7", 302 }, { "/reports/account-timeline.html", 302 }, { "/reports/generated.html", 403 }
    };
    [Theory, MemberData(nameof(Routes))]
    public async Task Every_operation_dispatches_with_the_reference_status(string path, int status)
    {
        var reader = new Reader(); using var host = await Host(reader); using var client = host.GetTestClient();
        using var response = await client.GetAsync(path, TestContext.Current.CancellationToken);
        Assert.Equal(status, (int)response.StatusCode);
        if (path == "/reports/ai-prompt-preview.html") {
            string html = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            Assert.Contains("&lt;script&gt;fixture&lt;/script&gt;", html); Assert.DoesNotContain("<script>", html);
        }
        if (status == 500) { var json = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!; Assert.Equal("internal_server_error", json["error"]!.ToString()); Assert.False(string.IsNullOrEmpty(json["internal_error_id"]!.ToString())); }
        if (path.StartsWith("/reports/generated") || path.Contains("domain-security-overview")) Assert.Contains("report_artifact_unclassified", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }
    [Theory, MemberData(nameof(Routes))]
    public async Task Capability_denial_or_artifact_guard_precedes_input_and_read(string path, int unused)
    {
        _ = unused; var reader = new Reader(); using var host = await Host(reader, allowed: false); using var client = host.GetTestClient();
        using var response = await client.GetAsync(path + (path.Contains('?') ? "&" : "?") + "limit=bad", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); Assert.Equal(0, reader.Calls);
    }
    [Theory, MemberData(nameof(Routes))]
    public async Task Anonymous_requests_follow_API_or_browser_auth_contract(string path, int unused)
    {
        _ = unused; var reader = new Reader(); using var host = await Host(reader, authenticated: false); using var client = host.GetTestClient();
        using var response = await client.GetAsync(path, TestContext.Current.CancellationToken);
        Assert.Equal(path.StartsWith("/api/") ? HttpStatusCode.Unauthorized : HttpStatusCode.Found, response.StatusCode); Assert.Equal(0, reader.Calls);
        if (path.StartsWith("/reports/")) Assert.StartsWith("/login?next=", response.Headers.Location!.ToString());
    }
    [Theory, MemberData(nameof(Routes))]
    public async Task Invalid_limit_matches_the_real_dispatcher_for_every_operation(string path, int normalStatus)
    {
        var reader = new Reader(); using var host = await Host(reader); using var client = host.GetTestClient();
        using var response = await client.GetAsync(path + (path.Contains('?') ? "&" : "?") + "limit=bad", TestContext.Current.CancellationToken);
        bool ignores = path.EndsWith("/summary") || path.Contains("/search") || path.Contains("/timeline") || path.Contains("ai-analysis.html") || normalStatus is 302 or 403;
        Assert.Equal(ignores ? normalStatus : path.Contains("preview") ? 400 : 500, (int)response.StatusCode);
    }
    [Theory]
    [InlineData("/reports/search.html?q=a%26b&limit=bad&server=one&server=two&offset=20", "/app/events?q=a%26b&server=one")]
    [InlineData("/reports/event-details.html?event_db_id=42", "/app/events/42")]
    [InlineData("/vpn-report", "/app/vpn-report")]
    [InlineData("/reports/storage-health.html?legacy=1", "/app/operations")]
    [InlineData("/reports/search-deep.html?risk=high&account=private&unknown=value", "/app/events?risk=high")]
    [InlineData("/reports/security-events-monitor.html?period=24h&q=hello+world", "/app/events?q=hello+world")]
    [InlineData("/reports/account-timeline.html?scope=important", "/app/investigations?scope=important")]
    [InlineData("/reports/event-details.html?id=7&event_db_id=&q=drop", "/app/events/7")]
    [InlineData("/reports/event-details.html?id=bad", "/app/events")]
    [InlineData("/reports/entity-details.html?entity_id=-2", "/app/entities")]
    public async Task Redirects_preserve_only_the_first_allowlisted_values(string path, string target)
    {
        var reader = new Reader(); using var host = await Host(reader); using var client = host.GetTestClient();
        using var response = await client.GetAsync(path, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, response.StatusCode); Assert.Equal(target, response.Headers.Location!.ToString()); Assert.Equal(0, reader.Calls);
    }
    [Theory, InlineData("/api/events/search"), InlineData("/api/entities/details"), InlineData("/api/ai/runs"), InlineData("/api/security/events-monitor")]
    public async Task Scoped_grants_cannot_authorize_global_legacy_reads(string path)
    {
        var reader = new Reader(); using var host = await Host(reader, scoped: true); using var client = host.GetTestClient();
        using var response = await client.GetAsync(path, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); Assert.Contains("resource_context_required", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)); Assert.Equal(0, reader.Calls);
    }
    [Theory, InlineData("/api/events/search?time_from=bad", "invalid_datetime"), InlineData("/api/entities/details?timezone=No/Such", "invalid_timezone"), InlineData("/api/events/timeline?time_from=2026-11-03&time_to=2026-11-01", "empty_or_reversed_time_range")]
    public async Task Invalid_time_range_is_400_without_data_access(string path, string code)
    {
        var reader = new Reader(); using var host = await Host(reader); using var client = host.GetTestClient();
        using var response = await client.GetAsync(path, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode); Assert.Contains(code, await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)); Assert.Equal(0, reader.Calls);
    }
    [Fact] public async Task Timeout_is_503_and_does_not_echo_exception_text()
    {
        var reader = new Reader { Error = new TimeoutException("private input") }; using var host = await Host(reader); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/entities/summary", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode); Assert.DoesNotContain("private input", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }
    [Theory]
    [InlineData("timeout")]
    [InlineData("postgres")]
    [InlineData("driver")]
    public async Task Report_artifact_timeout_is_structured_and_the_next_request_can_read(string failure)
    {
        var reader = new Reader { Error = failure switch
        {
            "postgres" => new Npgsql.PostgresException("private-database-value", "ERROR", "ERROR", "57014"),
            "driver" => new Npgsql.NpgsqlException("private-database-value", new TimeoutException("private-read")),
            _ => new TimeoutException("private-database-value")
        } };
        using var host = await Host(reader); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/reports/security-events-monitor.csv", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
        Assert.Equal(2, body.Count);
        Assert.Equal("report_read_timeout", body["error"]!.GetValue<string>());
        Assert.Equal("unavailable", body["state"]!.GetValue<string>());
        reader.Error = null;
        using var next = await client.GetAsync("/reports/security-events-monitor.csv", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, next.StatusCode); Assert.Equal(2, reader.Calls);
    }
}
