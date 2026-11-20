using System.Net;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Primitives;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Domains;
using Sli.Server.Infrastructure;
using Xunit;

namespace Sli.Server.Tests.Domains;

// Vectors from tests/access/test_domain_scope.py, through the actual .NET composers and routes.
public sealed class DomainScopeParityTests
{
    private static readonly Principal Viewer = new("session", 1, "viewer");
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-10-01T00:00:00+00:00");
    private static readonly string[] Fields = ["identity_basic", "security", "technical"];
    private static JsonElement Json(object value) => JsonSerializer.SerializeToElement(value);

    private sealed class Facts(AccessFacts value) : IAccessFactsRepository
    {
        public AccessFacts Value { get; set; } = value;
        public int Reads { get; private set; }
        public Task<AccessFacts> LoadAsync(Principal principal, CancellationToken ct)
        {
            Assert.Equal(Viewer, principal);
            Reads++;
            return Task.FromResult(Value);
        }
    }

    private static AccessFacts Authority(long[]? ids, string denial = "")
    {
        object scope = ids is null ? new { kind = "all" } : new { kind = "domain", ids };
        if (denial == "mixed") scope = new { mode = "restricted", clauses = new[] {
            new { device_ids = new[] { "server:1" }, collection_scope_ids = new[] { "ad-domain:7" } } } };
        return new(false, "viewer", [], [],
            (denial == "workspace" ? Fields.Select(f => "field." + f) : Fields.Select(f => "field." + f).Prepend("workspace.view"))
                .Select(key => Json(new { capability_key = key, effect = "allow", scope_json = new { kind = "all" } })).ToArray(),
            [], [], ids is { Length: 0 } ? [] : [Json(new { report_key = "ad.users.v2",
                effect = denial == "report" ? "deny" : "allow", scope_json = scope,
                field_categories = denial == "fields" ? Array.Empty<string>() : Fields,
                allowed_actions = new[] { denial == "grant_action" ? "export" : "view" } })],
            [Json(new { report_key = "ad.users.v2", version = 1, dataset_version = 1,
                definition_json = new { field_categories = Fields, actions = new[] { "view", "export" } },
                fields_json = Fields.Select(category => new { category }),
                actions_json = new[] { denial == "action" ? "export" : "view" } })]);
    }

    private sealed class NeverConnections : IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => throw new InvalidOperationException("Unexpected database access");
    }

    private sealed class Registry : IDomainRepository
    {
        public List<DomainGrant> Reads { get; } = [];
        public bool Fail { get; set; }
        public Task<IReadOnlyList<DomainItem>> ReadAsync(DomainGrant grant, CancellationToken ct)
        {
            if (grant.Kind == DomainGrantKind.None) return Task.FromResult<IReadOnlyList<DomainItem>>([]);
            Reads.Add(grant);
            if (Fail) throw new InvalidOperationException("synthetic read failure");
            return Task.FromResult<IReadOnlyList<DomainItem>>(new long[] { 7, 8 }
                .Where(id => grant.Kind == DomainGrantKind.All || grant.DomainIds.Contains(id))
                .Select(id => new DomainItem(id, $"domain-{id}.example.test", false,
                    new DomainFreshness("2026-10-01T00:00:00+00:00", null, "partial", "2026-10-01T00:00:00+00:00", null, null, null)))
                .ToArray());
        }
    }

    private sealed class NoReportReads : IHomeSummaryRepository
    {
        public Task<IReadOnlyList<JsonObject>> ReadAsync(string sql, IReadOnlyDictionary<string, object?> parameters, CancellationToken ct)
            => throw new InvalidOperationException("Domain selection must not query report data");
    }

    private static HomeSummaryService Selection(Facts facts, Registry registry) => new(
        new HomeSummaryAccess(new NeverConnections(), new ReportRuleCatalog(), facts), registry, new HomeSummaryReaders(new NoReportReads()));

    private static HomeSummaryQuery Query(long? domain = null) => HomeSummaryQuery.Parse(new QueryCollection(
        domain is null ? new Dictionary<string, StringValues>() : new() { ["domain_id"] = domain.ToString() }), Now);

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(-1)]
    public async Task ListsOnlyAccessibleRegisteredDomains(int count)
    {
        long[]? ids = count < 0 ? null : new long[] { 7, 8 }.Take(count).ToArray();
        var facts = new Facts(Authority(ids)); var registry = new Registry();
        using var host = Host(facts, registry);
        using var client = host.CreateClient();
        using var response = await client.GetAsync("/api/v1/domains", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        var items = json.RootElement.GetProperty("items").EnumerateArray().ToArray();
        Assert.Equal(ids ?? [7, 8], items.Select(i => i.GetProperty("id").GetInt64()));
        foreach (var item in items)
        {
            Assert.EndsWith(".example.test", item.GetProperty("display_name").GetString());
            Assert.Equal("2026-10-01T00:00:00+00:00", item.GetProperty("freshness").GetProperty("observed_at_utc").GetString());
            Assert.Equal(JsonValueKind.Null, item.GetProperty("freshness").GetProperty("event_at_utc").ValueKind);
        }
        Assert.Equal(count == 0 ? 0 : 1, registry.Reads.Count);
        Assert.Equal(1, facts.Reads);
    }

    [Theory]
    [InlineData("7", 8, false)]
    [InlineData("", 7, false)]
    [InlineData(null, 9, true)]
    [InlineData("7,9", 9, true)]
    public async Task ForeignAndUnknownDomainFailClosed(string? ids, long selected, bool reads)
    {
        var facts = new Facts(Authority(ids is null ? null : ids == "" ? [] : ids.Split(',').Select(long.Parse).ToArray()));
        var registry = new Registry();
        var error = await Assert.ThrowsAsync<HomeQueryException>(() => Selection(facts, registry).BuildAsync(Viewer, Query(selected), TestContext.Current.CancellationToken));
        Assert.Equal("domain_scope_denied", error.Message); Assert.Equal(403, error.Status);
        Assert.Equal(reads ? 1 : 0, registry.Reads.Count);
        if (reads) Assert.Equal(new[] { selected }, registry.Reads[0].DomainIds);
    }

    public static TheoryData<string[]> InvalidSelectors => new()
    {
        Array.Empty<string>(), new[] { "" }, new[] { "0" }, new[] { "-1" }, new[] { "7", "8" },
        new[] { "all" }, new[] { " 7" }, new[] { "7.0" }, new[] { new string('9', 20) }, new[] { "9223372036854775808" }
    };

    [Theory]
    [MemberData(nameof(InvalidSelectors))]
    public void ExplicitInvalidDomainNeverBecomesAll(string[] values)
    {
        var query = new QueryCollection(new Dictionary<string, StringValues> { ["domain_id"] = new(values) });
        Assert.Equal("domain_scope_invalid", Assert.Throws<HomeQueryException>(() => DomainQuery.ParseDomainId(query)).Message);
    }

    [Fact]
    public void AbsentSelectorAndBigintBoundaryAreDistinct()
    {
        Assert.Null(DomainQuery.ParseDomainId(QueryCollection.Empty));
        foreach (var id in new[] { 7L, long.MaxValue })
            Assert.Equal(id, DomainQuery.ParseDomainId(new QueryCollection(new Dictionary<string, StringValues> { ["domain_id"] = id.ToString() })));
    }

    [Theory]
    [InlineData("report")]
    [InlineData("action")]
    [InlineData("grant_action")]
    [InlineData("fields")]
    [InlineData("mixed")]
    public async Task UnexecutableReportNeverQueriesDomains(string denial)
    {
        var facts = new Facts(Authority([7], denial)); var registry = new Registry();
        var result = await Selection(facts, registry).BuildAsync(Viewer, Query(), TestContext.Current.CancellationToken);
        Assert.Empty(result["domain_scope"]!["domain_ids"]!.AsArray());
        Assert.Empty(registry.Reads);
    }

    [Fact]
    public void RequiredReportCapabilityCannotBeBypassedByDomainRegistry()
    {
        var grant = new AtomicReportGrant(Json(new { kind = "domain", ids = new[] { 7L } }), new HashSet<string>(), new HashSet<string> { "view" }, 1, 1);
        var access = new AccessDecision("viewer", new(false, new HashSet<string> { "workspace.view" }, new HashSet<string>(), [], new Dictionary<string, JsonElement>()),
            [new("synthetic", true, [grant])]);
        var rule = new ReportRule("synthetic", "synthetic", "domain", new HashSet<string>(), new HashSet<string> { "synthetic.view" }, null, false);
        Assert.Equal(DomainGrantKind.None, new ReportScopeResolver().PermittedDomains(access, [rule]).Kind);
    }

    [Fact]
    public async Task RegistryUnionsOnlyCurrentUsersExecutableRegisteredReports()
    {
        var first = Authority([7]); var second = Authority([8]); var unregistered = Authority([9]);
        JsonElement Rename(JsonElement row, string key)
        {
            var obj = JsonNode.Parse(row.GetRawText())!.AsObject(); obj["report_key"] = key; return Json(obj);
        }
        var facts = new Facts(first with {
            ReportAssignments = [..first.ReportAssignments, Rename(second.ReportAssignments[0], "ad.computers.v6"), Rename(unregistered.ReportAssignments[0], "unregistered")],
            Definitions = [..first.Definitions, Rename(second.Definitions[0], "ad.computers.v6"), Rename(second.Definitions[0], "unregistered")] });
        var service = new DomainAccessService(new NeverConnections(), facts: facts);
        var decision = await service.EvaluateAsync(Viewer, TestContext.Current.CancellationToken);
        Assert.Equal(new long[] { 7, 8 }, decision.Grant.DomainIds.Order());
        facts.Value = Authority([7]);
        decision = await service.EvaluateAsync(Viewer, TestContext.Current.CancellationToken);
        Assert.Equal(new long[] { 7 }, decision.Grant.DomainIds.Order());
    }

    [Fact]
    public async Task RevocationIsCheckedAgainWithoutSharedSelectionCache()
    {
        var facts = new Facts(Authority([7, 8])); var registry = new Registry(); var service = Selection(facts, registry);
        var result = await service.BuildAsync(Viewer, Query(8), TestContext.Current.CancellationToken);
        Assert.Equal(8, result["domain_scope"]!["domain_ids"]![0]!.GetValue<long>());
        facts.Value = Authority([7]);
        Assert.Equal("domain_scope_denied", (await Assert.ThrowsAsync<HomeQueryException>(() => service.BuildAsync(Viewer, Query(8), TestContext.Current.CancellationToken))).Message);
        Assert.Single(registry.Reads); Assert.Equal(2, facts.Reads);
    }

    [Fact]
    public async Task RegistryFailureIsNotAnEmptyList()
    {
        var facts = new Facts(Authority([7])); var registry = new Registry { Fail = true };
        Assert.Equal("synthetic read failure", (await Assert.ThrowsAsync<InvalidOperationException>(() => Selection(facts, registry).BuildAsync(Viewer, Query(), TestContext.Current.CancellationToken))).Message);
        using var host = Host(facts, registry); using var client = host.CreateClient();
        using var response = await client.GetAsync("/api/v1/domains", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("internal_server_error", body); Assert.DoesNotContain("synthetic read failure", body);
    }

    [Theory]
    [InlineData("", 403, "workspace_view_required", 1)]
    [InlineData("?domain_id=7", 400, "domain_parameters_invalid", 0)]
    public async Task DomainEndpointRequiresWorkspaceAndRejectsFiltersFirst(string query, int status, string error, int factReads)
    {
        var facts = new Facts(Authority([7], "workspace")); var registry = new Registry();
        using var host = Host(facts, registry); using var client = host.CreateClient();
        using var response = await client.GetAsync("/api/v1/domains" + query, TestContext.Current.CancellationToken);
        Assert.Equal(status, (int)response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.Equal(error, json.RootElement.GetProperty("error").GetString());
        Assert.Empty(registry.Reads); Assert.Equal(factReads, facts.Reads);
    }

    [Fact]
    public void DomainFreshnessSqlFiltersBeforeAggregationAndAvoidsEventHistory()
    {
        var sql = (string)typeof(DomainRepository).GetField("DomainSql", BindingFlags.NonPublic | BindingFlags.Static)!.GetRawConstantValue()!;
        Assert.Contains("where (cast(@ids as bigint[]) is null or d.id=any(cast(@ids as bigint[])))", sql);
        Assert.Contains("s.domain_id=d.id", sql); Assert.Contains("other.id<>s.id", sql);
        Assert.DoesNotContain("from events_v2_core", sql);
    }

    private sealed class Authentication : IPrincipalAuthenticator
    {
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext context, CancellationToken ct) => ValueTask.FromResult(AuthenticationResult.Success(Viewer));
    }

    private sealed class RawTargetFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use(async (context, runNext) => {
                context.Features.Get<IHttpRequestFeature>()!.RawTarget = context.Request.Path + context.Request.QueryString;
                await runNext(context);
            });
            next(app);
        };
    }

    private static WebApplicationFactory<Program> Host(Facts facts, Registry registry) => new WebApplicationFactory<Program>().WithWebHostBuilder(Sli.Server.Tests.Domains.SafeTestEnvironment.ConfigureApiHost).WithWebHostBuilder(builder =>
    {
        builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?> {
            ["Sli:AuthAllowInsecureHttp"] = "1", ["Sli:TrustedProxies"] = "", ["Sli:OwnerSetup"] = "0" }));
        builder.ConfigureServices(services => {
            services.RemoveAll<IPrincipalAuthenticator>(); services.AddSingleton<IPrincipalAuthenticator, Authentication>();
            services.RemoveAll<IAccessFactsRepository>(); services.AddSingleton<IAccessFactsRepository>(facts);
            services.RemoveAll<IDomainAccessService>(); services.AddSingleton<IDomainAccessService>(new DomainAccessService(new NeverConnections(), facts: facts));
            services.RemoveAll<IDomainRepository>(); services.AddSingleton<IDomainRepository>(registry);
            services.AddTransient<IStartupFilter, RawTargetFilter>();
        });
    });
}
