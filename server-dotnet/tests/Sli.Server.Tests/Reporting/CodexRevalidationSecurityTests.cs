using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Agents;
using Sli.Server.Domains;
using Sli.Server.Entities;
using Sli.Server.Infrastructure;
using Sli.Server.Legacy;
using Sli.Server.Reporting;
using Sli.Server.Workspace;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Reporting;

// Behavioral vectors from tests/reporting/test_codex_revalidation_security.py.
public sealed class CodexRevalidationSecurityTests
{
    private static JsonElement J(string json) => JsonSerializer.Deserialize<JsonElement>(json);
    private static JsonObject O(string json) => JsonNode.Parse(json)!.AsObject();
    private static AccessFacts Facts(params JsonElement[] policies) => new(false, "viewer", [], [], policies, [], [], [], []);
    private static CapabilityDecisionSet Caps(params string[] keys) => new(false, keys.ToHashSet(), new HashSet<string>(), [], new Dictionary<string, JsonElement>());

    [Fact]
    public void SensitiveFieldsAndActionsAreBoundedByCapabilitiesWithinOneGrant()
    {
        var facts = Facts(J("""{"capability_key":"field.identity_basic","effect":"allow","scope_json":{"kind":"all"}}""")) with
        {
            ReportAssignments = [J("""{"report_key":"tuple.test","effect":"allow","scope_json":{"kind":"server","ids":[7]},"field_categories":["identity_basic","raw_evidence"],"allowed_actions":["view","export"]}""")],
            Definitions = [J("""{"report_key":"tuple.test","version":1,"dataset_version":1,"definition_json":{"actions":["view","export"]},"actions_json":["view","export"],"fields_json":[{"category":"identity_basic"},{"category":"raw_evidence"}]}""")]
        };
        var report = Assert.Single(new ReportEligibility().Compose(facts, new CapabilityComposer().Compose(facts)).Reports);
        Assert.True(report.Allowed);
        var grant = Assert.Single(report.Grants);
        Assert.Equal(new[] { "identity_basic" }, grant.FieldCategories);
        Assert.Equal(new[] { "view" }, grant.AllowedActions);
        Assert.Equal(7, grant.Scope.GetProperty("ids")[0].GetInt32());
    }

    [Theory]
    [InlineData("all", true)]
    [InlineData("server", false)]
    public void ScopedCapabilityNeverBecomesGlobal(string kind, bool global)
    {
        var facts = Facts(J(kind == "all"
            ? """{"capability_key":"workspace.view","effect":"allow","scope_json":{"kind":"all"}}"""
            : """{"capability_key":"workspace.view","effect":"allow","scope_json":{"kind":"server","ids":[7]}}"""));
        var caps = new CapabilityComposer().Compose(facts);
        Assert.Equal(global, caps.Decide("workspace.view").Allowed);
        Assert.Equal(global, Assert.Single(caps.Policies).Global);
    }

    [Fact]
    public void PolicyDiagnosticsSurviveResponseSerialization()
    {
        var facts = Facts(J("""{"capability_key":"workspace.view","effect":"allow","scope_json":{"kind":"server","ids":[7]}}"""),
            J("""{"capability_key":"field.technical","effect":"allow","scope_json":{"kind":"server","ids":[]}}"""));
        var caps = new CapabilityComposer().Compose(facts);
        var json = JsonSerializer.SerializeToElement(AccessReadProjection.Compose(new("session", 1, "viewer"), facts, caps, new ReportEligibility().Compose(facts, caps), false));
        Assert.Equal("invalid_scope", Assert.Single(json.GetProperty("quarantined_capability_assignments").EnumerateArray()).GetProperty("reason").GetString());
        Assert.Equal("resource_context_required", Assert.Single(json.GetProperty("resource_bound_capability_assignments").EnumerateArray()).GetProperty("reason").GetString());
    }

    [Fact]
    public void ColumnExpansionAndMetricValuePathChangeRequireSecurityReapproval()
    {
        var before = O("""{"columns":["name"],"actions":["view"],"field_categories":["identity_basic"],"dashboard_metrics":[{"key":"objects.total","kind":"required","value_path":"summary.total","target_path":"/reports/objects","filters":{}}]}""");
        Assert.False(ReportBuilder.SecurityExpands(before, (JsonObject)before.DeepClone()));
        var expanded = (JsonObject)before.DeepClone(); expanded["columns"]!.AsArray().Add("sid");
        Assert.True(ReportBuilder.SecurityExpands(before, expanded));
        var metric = (JsonObject)before.DeepClone(); metric["dashboard_metrics"]![0]!["value_path"] = "summary.enabled";
        Assert.True(ReportBuilder.SecurityExpands(before, metric));
    }

    [Theory]
    [InlineData("field.technical", "object_sid")]
    [InlineData("field.hr", "department")]
    [InlineData("field.contact", "email")]
    public void ObjectAttributesAreProjectedByCategoryAndUnknownIsAlwaysDenied(string capability, string expected)
    {
        var context = O("""{"items":[{"context_kind":"entity","attributes":{"object_sid":"S-1-5-21-100000001-200000002-300000003-7","department":"Finance","email":"alice@example.test","unknown_secret":"hidden"}}]}""");
        var projected = EntityDirectoryReader.Project(context, Caps(capability), new JsonObject(), true);
        var attributes = projected["items"]![0]!["attributes"]!.AsObject();
        Assert.Equal(new[] { expected }, attributes.Select(p => p.Key));
        Assert.Equal(context["items"]![0]!["attributes"]![expected]!.ToString(), attributes[expected]!.ToString());
        Assert.True(context["items"]![0]!["attributes"]!.AsObject().ContainsKey("unknown_secret"));
        var combined = EntityDirectoryReader.Project(context, Caps("field.hr", "field.contact"), new JsonObject(), true);
        Assert.Equal(new[] { "department", "email" }, combined["items"]![0]!["attributes"]!.AsObject().Select(p => p.Key));
    }

    private sealed class NoConnections : IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => throw new InvalidOperationException("No database should be read for an empty session cookie");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task MissingCookieDoesNotShareAccessFactsBetweenPrincipals(string? cookie)
    {
        var cache = new SessionAccessFactsCache(new NoConnections(), TimeProvider.System);
        var seen = new List<long>();
        async Task<AccessFacts> Load(long id)
        {
            return await cache.LoadAsync(new("session", id, "viewer"), cookie, () => { seen.Add(id); return Task.FromResult(Facts()); }, TestContext.Current.CancellationToken);
        }
        Assert.NotSame(await Load(1), await Load(2));
        Assert.Equal(new long[] { 1, 2 }, seen);
    }

    [Fact]
    public async Task ScopeTargetsAreResolvedOnTheServer()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var pg = new PostCollectionPostgres(); await pg.StartAsync(ct);
        await using var db = await pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db, "create table servers(id bigint); insert into servers values(7); create table storage_v2_channel(value text); insert into storage_v2_channel values('Security');", ct);
        await using var tx = await db.BeginTransactionAsync(ct);
        await ReportAssignmentWriter.ValidateTargetsAsync(tx, "server", J("""{"ids":[7]}"""), ct);
        var error = await Assert.ThrowsAsync<AssignmentValidationException>(() => ReportAssignmentWriter.ValidateTargetsAsync(tx, "server", J("""{"ids":[7,8]}"""), ct));
        Assert.Equal("report_scope_target_not_found", error.Message);
        await ReportAssignmentWriter.ValidateTargetsAsync(tx, "channel", J("""{"values":["Security"]}"""), ct);
    }

    [Fact]
    public void RuleBasedRecommendationReportIsLabelledLocalRules()
    {
        var context = LegacyReportContext.Build(1, ["dc.example.test"], [], null, null, [], false);
        Assert.Equal("local_rules", context["analysis_mode"]!.ToString());
        Assert.DoesNotContain("AI Security Report:", LegacyReportTemplate.Render(context));
    }

    private sealed class CapturedLog : ILogger
    {
        public List<string> Messages = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => true;
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        { Assert.Null(exception); Messages.Add(formatter(state, exception)); }
    }

    [Fact]
    public async Task ErrorLogContainsOnlyRouteAndNeverQueryOrExceptionValues()
    {
        using var services = new ServiceCollection().BuildServiceProvider();
        var context = new DefaultHttpContext { RequestServices = services };
        context.Request.Path = "/api/v1/events"; context.Request.QueryString = new("?q=do-not-log&sid=do-not-log");
        context.Response.Body = new MemoryStream(); var log = new CapturedLog();
        await DomainHttp.WriteUnexpectedAsync(context, log, new InvalidOperationException("do-not-log"), TestContext.Current.CancellationToken, context.Request.Path);
        Assert.Contains("route=/api/v1/events", Assert.Single(log.Messages));
        Assert.DoesNotContain("do-not-log", log.Messages[0]);
        Assert.Equal(500, context.Response.StatusCode);
        context.Response.Body.Position = 0;
        using var response = await JsonDocument.ParseAsync(context.Response.Body, cancellationToken: TestContext.Current.CancellationToken);
        Assert.DoesNotContain("do-not-log", response.RootElement.GetRawText());
    }

    private sealed class Admin : IPrincipalAuthenticator
    {
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext context, CancellationToken ct) =>
            ValueTask.FromResult(AuthenticationResult.Success(new("session", 1, "admin")));
    }
    private sealed class EmptyFacts : IAccessFactsRepository
    {
        public Task<AccessFacts> LoadAsync(Principal principal, CancellationToken ct) => Task.FromResult(Facts() with { Role = principal.Role });
    }

    [Fact]
    public async Task AdminAgentRoutesAndDashboardRequireTheirExplicitCapabilities()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:AuthRequired"] = "1" }).Build();
        using var host = await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(services =>
        {
            services.AddRouting(); services.AddLogging(); services.AddSingleton<IConfiguration>(config);
            services.AddSingleton(new AuthRequestPolicy(config)); services.AddSingleton(new TransportGate(config));
            services.AddSingleton<IPrincipalAuthenticator, Admin>(); services.AddSingleton<IAccessFactsRepository, EmptyFacts>();
            services.AddSingleton<IPostgresConnectionFactory, NoConnections>();
        }).Configure(app =>
        {
            // TestServer leaves RawTarget empty; Kestrel supplies the wire path.
            app.Use((context, next) => { context.Features.Get<IHttpRequestFeature>()!.RawTarget = context.Request.Path + context.Request.QueryString; return next(context); });
            app.UseRouting(); app.UseEndpoints(endpoints => { endpoints.MapAgentUpdateAdministrationEndpoints(); endpoints.MapWorkspaceCompatibility(); });
        })).StartAsync(TestContext.Current.CancellationToken);
        using var client = host.GetTestClient();
        foreach (var (method, path, capability) in new[] { ("GET", "/api/v1/admin/agent-packages", "access.manage"), ("POST", "/api/v1/admin/agents/update-policy", "access.manage"), ("GET", "/api/dashboard/snapshot", "workspace.view") })
        {
            using var request = new HttpRequestMessage(new HttpMethod(method), path);
            using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
            Assert.Equal(403, (int)response.StatusCode);
            var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
            Assert.Equal(capability, body["required_capability"]!.ToString());
        }
    }
}
