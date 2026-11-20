using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Ad;
using Sli.Server.Gpo;
using Sli.Server.Domains;
using Sli.Server.Workspace;
using Sli.Server.Infrastructure;
using Sli.Server.Reporting.V2;
using Sli.Server.Tests.Reporting;
using Sli.Server.Tests.Gpo;
using Xunit;

namespace Sli.Server.Tests.Access;

public sealed class ReportCatalogRegistrationTests
{
    private static JsonElement Json(string json) => JsonSerializer.Deserialize<JsonElement>(json);
    private static ReportRule Rule(params string[] fields) => new("ad.infrastructure", "ad.state", "domain",
        fields.ToHashSet(), new HashSet<string>(), null, false) { OwnerId = "sli.ad" };

    [Fact]
    public void DeclarationPayloadsAndDomainDecisionsMatchPythonRegistryLifecycle()
    {
        using var stream = typeof(ReportCatalogRegistrationTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Access.catalog-lifecycle-source.json")!;
        using var vectors = JsonDocument.Parse(stream);
        Assert.Equal("ddce909d0ddebe43a670e63c85df369e0bd16f17", vectors.RootElement.GetProperty("source_commit").GetString());
        using var files = new ReportCatalogLifecycleTests.CatalogFiles();
        var snapshots = new List<ReportCatalogSnapshot>();
        foreach (var test in vectors.RootElement.GetProperty("cases").EnumerateArray())
        {
            string? generation = test.GetProperty("generation").GetString();
            if (generation is null) files.Rollback("sli.ad"); else files.Activate("sli.ad", generation);
            bool fenced = test.GetProperty("fenced").GetBoolean();
            if (fenced) files.Fence("sli.ad"); else files.Unfence("sli.ad");
            // Drain hides a retained contribution; it does not replace it with an empty hook.
            if (!fenced)
                files.Catalog.Register("sli.ad", generation, test.GetProperty("declarations").EnumerateArray().Select(d =>
                    Rule(d.GetProperty("required_fields").EnumerateArray().Select(f => f.GetString()!).ToArray()) with {
                        RequiredCapabilities = d.GetProperty("required_capabilities").EnumerateArray().Select(c => c.GetString()!).ToHashSet()
                    }));
            var snapshot = files.Catalog.Capture();
            snapshots.Add(snapshot);
            var payload = JsonSerializer.SerializeToElement(snapshot.Rules.Where(r => r.OwnerId == "sli.ad").Select(r => new {
                key = r.RegistryKey, report_key = r.ReportKey, scope = r.Scope,
                required_fields = r.RequiredFields.Order().ToArray(), required_capabilities = r.RequiredCapabilities.Order().ToArray()
            }));
            Assert.True(JsonElement.DeepEquals(test.GetProperty("declarations"), payload), test.GetProperty("name").GetString());
            var caps = new CapabilityDecisionSet(false,
                test.GetProperty("capabilities").EnumerateArray().Select(c => c.GetString()!).ToHashSet(), new HashSet<string>(), [], new Dictionary<string, JsonElement>());
            var grant = new AtomicReportGrant(Json("""{"kind":"all"}"""), new HashSet<string> { "technical" }, new HashSet<string> { "view" }, 11, 4);
            var decision = new AccessDecision("viewer", caps, [new("ad.state", true, [grant])]);
            var actual = new ReportScopeResolver().PermittedDomains(decision, snapshot.Rules);
            var expected = test.GetProperty("permitted_domain_ids");
            if (expected.ValueKind == JsonValueKind.Null) Assert.Equal(DomainGrantKind.All, actual.Kind);
            else { Assert.NotEqual(DomainGrantKind.All, actual.Kind); Assert.Equal(expected.EnumerateArray().Select(i => i.GetInt64()), actual.DomainIds.Order()); }
        }
        Assert.Single(snapshots[0].Rules, r => r.OwnerId == "sli.ad");
        Assert.Equal(new[] { "technical" }, snapshots[0].Rules.Single(r => r.OwnerId == "sli.ad").RequiredFields);
        Assert.DoesNotContain(files.Catalog.Recheck(snapshots[3]).Rules, r => r.OwnerId == "sli.ad"); // no denial upgrade
    }

    [Fact]
    public void RegistrationCopiesMutableInputAndInvalidatesSameGenerationAndEnableAba()
    {
        using var files = new ReportCatalogLifecycleTests.CatalogFiles();
        var fields = new HashSet<string> { "technical" };
        var input = new List<ReportRule> { Rule() with { RequiredFields = fields } };
        files.Catalog.Register("sli.ad", null, input);
        var before = files.Catalog.Capture();
        fields.Add("security"); input.Clear();
        Assert.Equal(new[] { "technical" }, before.Rules.Single(r => r.OwnerId == "sli.ad").RequiredFields);
        Assert.Equal(new[] { "technical" }, files.Catalog.Capture().Rules.Single(r => r.OwnerId == "sli.ad").RequiredFields);
        files.Catalog.Register("sli.ad", null, [Rule("technical")]);
        Assert.Equal("plugin_version_changed", files.Catalog.Recheck(before).UnavailableOwners["sli.ad"]);
        var registered = files.Catalog.Capture();
        files.Catalog.SetEnabled("sli.ad", false);
        var disabled = files.Catalog.Capture();
        Assert.Equal("plugin_disabled", disabled.UnavailableOwners["sli.ad"]);
        files.Catalog.SetEnabled("sli.ad", true);
        Assert.Equal("plugin_version_changed", files.Catalog.Recheck(registered).UnavailableOwners["sli.ad"]);
        Assert.Equal("plugin_disabled", files.Catalog.Recheck(disabled).UnavailableOwners["sli.ad"]);
        Assert.Single(files.Catalog.Capture().Rules, r => r.OwnerId == "sli.ad");
        Assert.Throws<ArgumentException>(() => new ReportRuleCatalog(new PluginGenerationReader(null)).Recheck(before));
        var enabled = files.Catalog.Capture();
        files.Catalog.SetEnabled("sli.ad", false);
        files.Fence("sli.ad");
        Assert.Equal("plugin_update_draining", files.Catalog.Recheck(enabled).UnavailableOwners["sli.ad"]);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("scope")]
    [InlineData("owner")]
    [InlineData("duplicate")]
    [InlineData("unknown")]
    public void MissingOrUnrepresentableDeclarationNeverRestoresBundledAll(string fault)
    {
        using var files = new ReportCatalogLifecycleTests.CatalogFiles();
        files.Catalog.Register("sli.ad", null, [Rule("technical")]);
        var old = files.Catalog.Capture();
        ReportRule[]? replacement = fault switch {
            "missing" => null,
            "scope" => [Rule() with { Scope = "unrepresentable" }],
            "owner" => [Rule() with { OwnerId = "sli.core", GuardedContribution = false }],
            "duplicate" => [Rule(), Rule()],
            _ => [Rule() with { RegistryKey = "events.journal" }]
        };
        if (fault == "missing") files.Catalog.Register("sli.ad", null, replacement);
        else Assert.Throws<InvalidOperationException>(() => files.Catalog.Register("sli.ad", null, replacement));
        var after = files.Catalog.Capture();
        Assert.Equal("plugin_report_declaration_unrepresentable", after.UnavailableOwners["sli.ad"]);
        Assert.DoesNotContain(after.Rules, r => r.OwnerId == "sli.ad");
        Assert.Equal(22, after.Rules.Count);
        Assert.DoesNotContain(files.Catalog.Recheck(old).Rules, r => r.OwnerId == "sli.ad");
        files.Catalog.Register("sli.ad", null, []);
        Assert.DoesNotContain(files.Catalog.Capture().Rules, r => r.OwnerId == "sli.ad");
        Assert.DoesNotContain(files.Catalog.Recheck(after).Rules, r => r.OwnerId == "sli.ad");
    }

    [Fact]
    public async Task RegistrationRacesTheRealFactsCompositionWithoutMutatingPublishedVersions()
    {
        using var files = new ReportCatalogLifecycleTests.CatalogFiles();
        var facts = Facts();
        string unchanged = JsonSerializer.Serialize(facts);
        files.Catalog.Register("sli.ad", null, [Rule("technical")]);
        var source = new PausedFacts(facts);
        var service = new DomainAccessService(new NoConnections(), files.Catalog, source);
        var pending = service.EvaluateAsync(new Principal("session", 123, "viewer"), TestContext.Current.CancellationToken);
        await source.Started.Task.WaitAsync(TestContext.Current.CancellationToken);
        files.Catalog.Register("sli.ad", null, [Rule("technical")]);
        source.Continue.SetResult();
        Assert.Equal(DomainGrantKind.None, (await pending).Grant.Kind);
        Assert.Equal(DomainGrantKind.All, (await service.EvaluateAsync(new Principal("session", 123, "viewer"), TestContext.Current.CancellationToken)).Grant.Kind);
        files.Catalog.SetEnabled("sli.ad", false);
        Assert.Equal(DomainGrantKind.None, (await service.EvaluateAsync(new Principal("session", 123, "viewer"), TestContext.Current.CancellationToken)).Grant.Kind);
        files.Catalog.SetEnabled("sli.ad", true);
        var reports = new ReportEligibility().Compose(facts, new CapabilityComposer().Compose(facts));
        var grant = Assert.Single(Assert.Single(reports.Reports).Grants);
        Assert.Equal(11, grant.ReportVersion); Assert.Equal(4, grant.DatasetVersion);
        Assert.Equal(unchanged, JsonSerializer.Serialize(facts));
    }

    [Fact]
    public async Task DeclarationRegistrationCannotBorrowAnOldReaderOrReturnItsMetadata()
    {
        using var files = new ReportCatalogLifecycleTests.CatalogFiles();
        var rule = files.Catalog.Capture().Rules.Single(r => r.RegistryKey == ReportFixture.Key);
        files.Catalog.Register("sli.file-audit", null, [rule]);
        var registered = files.Catalog.Capture().Rules.Single(r => r.RegistryKey == ReportFixture.Key);
        var error = Assert.Throws<ReportRequestException>(() => new ReportV2Dispatcher([]).Resolve(registered));
        Assert.Equal("plugin_callable_generation_unsupported", error.Message);
        await using var host = await ReportFixture.Start(catalog: files.Catalog);
        foreach (string action in new[] { "", "/data", "/export.csv", "/rows/1/detail" })
        {
            using var response = await host.Client.GetAsync($"/api/v2/reports/{ReportFixture.Key}{action}", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
            Assert.Equal("plugin_callable_generation_unsupported", Json(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).GetProperty("error").GetString());
        }
        Assert.Equal(0, host.Reader.Calls);
    }

    [Fact]
    public async Task WorkspaceAndHomeDoNotAdvertiseDeclarationOnlyContributionsAsExecutable()
    {
        using var files = new ReportCatalogLifecycleTests.CatalogFiles();
        var facts = Facts();
        var home = new HomeSummaryAccess(new NoConnections(), files.Catalog, new ReportFixture.FactsRepo(facts));
        var principal = new Principal("session", 123, "viewer");
        Assert.Contains(await home.LoadAsync(principal, TestContext.Current.CancellationToken), r => r.Rule.RegistryKey == "ad.infrastructure");
        files.Catalog.Register("sli.ad", null, [Rule("technical")]);
        Assert.DoesNotContain(await home.LoadAsync(principal, TestContext.Current.CancellationToken), r => r.Rule.RegistryKey == "ad.infrastructure");
        var caps = new CapabilityComposer().Compose(facts);
        var reports = new ReportEligibility().Compose(facts, caps);
        var output = JsonSerializer.SerializeToElement(WorkspaceReportCatalog.Compose(new AccessReadEvaluation(facts, caps, reports), files.Catalog.Capture().Rules, []));
        var item = Assert.Single(output.GetProperty("items").EnumerateArray(), i => i.GetProperty("key").GetString() == "ad.infrastructure");
        Assert.False(item.GetProperty("executable").GetBoolean());
    }

    [Theory]
    [InlineData("sli.ad", "ad.infrastructure", "ad.state")]
    [InlineData("sli.gpo", "ad.gpo.v2", "ad.gpo.v2")]
    public async Task DedicatedRoutesAlsoRejectDeclarationOnlyGenerations(string owner, string key, string accessKey)
    {
        using var files = new ReportCatalogLifecycleTests.CatalogFiles();
        var rule = files.Catalog.Capture().Rules.Single(r => r.RegistryKey == key);
        files.Catalog.Register(owner, null, [rule]);
        var facts = JsonSerializer.Deserialize<AccessFacts>(JsonSerializer.Serialize(Facts()).Replace("ad.state", accessKey, StringComparison.Ordinal))!;
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:AuthRequired"] = "true" }).Build();
        using var host = await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(s => {
            s.AddRouting(); s.AddLogging(); s.AddSingleton<IConfiguration>(config);
            s.AddSingleton(new AuthRequestPolicy(config)); s.AddSingleton(new TransportGate(config));
            s.AddSingleton<IPrincipalAuthenticator>(new ReportFixture.Auth());
            s.AddSingleton<IAccessFactsRepository>(new ReportFixture.FactsRepo(facts));
            s.AddSingleton<IReportCatalogProvider>(files.Catalog);
            // No stores: refusing the contribution must happen before any database call.
        }).Configure(app => { app.UseRouting(); app.UseEndpoints(e => { e.MapAdV2(); e.MapGpoReports(); }); }))
            .StartAsync(TestContext.Current.CancellationToken);
        using var client = host.GetTestClient();
        foreach (string action in new[] { "", "/data", "/export.csv", "/rows/1/detail" })
        {
            using var response = await client.GetAsync($"/api/v2/reports/{key}{action}", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        }
    }

    [Theory]
    [InlineData("sli.ad", "ad.infrastructure", "")]
    [InlineData("sli.gpo", "ad.gpo.v2", "/data")]
    public async Task DedicatedRoutesRecheckAfterAwaitedPluginReads(string owner, string key, string action)
    {
        using var files = new ReportCatalogLifecycleTests.CatalogFiles();
        var rule = files.Catalog.Capture().Rules.Single(r => r.RegistryKey == key);
        var facts = Facts() with { IsOwner = true, Definitions = [JsonSerializer.SerializeToElement(new {
            report_key = rule.ReportKey, version = 11, dataset_version = 4,
            definition_json = new { field_categories = rule.RequiredFields, actions = new[] { "view" } },
            fields_json = rule.RequiredFields.Select(category => new { category }), actions_json = new[] { "view" }
        })] };
        var store = new RacingStores(() => files.Catalog.SetEnabled(owner, false));
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:AuthRequired"] = "true" }).Build();
        using var host = await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(s => {
            s.AddRouting(); s.AddLogging(); s.AddSingleton<IConfiguration>(config);
            s.AddSingleton(new AuthRequestPolicy(config)); s.AddSingleton(new TransportGate(config));
            s.AddSingleton<IPrincipalAuthenticator>(new ReportFixture.Auth());
            s.AddSingleton<IAccessFactsRepository>(new ReportFixture.FactsRepo(facts));
            s.AddSingleton<IReportCatalogProvider>(files.Catalog);
            s.AddSingleton<IAdV2Store>(store); s.AddSingleton<IGpoReadStore>(store);
        }).Configure(app => { app.UseRouting(); app.UseEndpoints(e => { e.MapAdV2(); e.MapGpoReports(); }); }))
            .StartAsync(TestContext.Current.CancellationToken);
        using var client = host.GetTestClient();
        using var response = await client.GetAsync($"/api/v2/reports/{key}{action}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("report_plugin_unavailable", Json(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).GetProperty("error").GetString());
        Assert.Equal(1, store.Reads);
    }

    private sealed class RacingStores(Action duringRead) : IAdV2Store, IGpoReadStore
    {
        private readonly GpoReportTests.Store gpo = new();
        public int Reads { get; private set; }
        public async Task<IReadOnlyList<JsonObject>> DomainsAsync(DomainGrant grant, CancellationToken ct)
        { await Task.Yield(); Reads++; duringRead(); return []; }
        public Task<JsonObject> ReadAsync(AdV2Request request, Func<IEnumerable<string>, bool> fields, CancellationToken ct)
            => throw new InvalidOperationException("The declaration race must be refused before reading AD data.");
        public async Task<JsonObject> PairAsync(long[]? domains, CancellationToken ct)
        { await Task.Yield(); Reads++; duringRead(); return await gpo.PairAsync(domains, ct); }
        public Task<JsonObject> GraphAsync(JsonObject snapshot, long[]? domains, CancellationToken ct) => gpo.GraphAsync(snapshot, domains, ct);
        public Task<JsonObject> HistoryAsync(long[]? domains, DateTimeOffset from, DateTimeOffset to, string query, CancellationToken ct) => gpo.HistoryAsync(domains, from, to, query, ct);
    }

    private static AccessFacts Facts() => new(false, "viewer", [], [],
        new[] { "workspace.view", "field.technical" }.Select(key => JsonSerializer.SerializeToElement(new { capability_key = key, effect = "allow", scope_json = new { kind = "all" } })).ToArray(), [], [],
        [Json("""{"report_key":"ad.state","effect":"allow","scope_json":{"kind":"all"},"field_categories":["technical"],"allowed_actions":["view"]}""")],
        [Json("""{"report_key":"ad.state","version":11,"dataset_version":4,"definition_json":{"field_categories":["technical"],"actions":["view"]},"fields_json":[{"category":"technical"}],"actions_json":["view"]}""")]);

    private sealed class PausedFacts(AccessFacts facts) : IAccessFactsRepository
    {
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Continue { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async Task<AccessFacts> LoadAsync(Principal principal, CancellationToken ct)
        { Started.TrySetResult(); await Continue.Task.WaitAsync(ct); return facts; }
    }
    private sealed class NoConnections : IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => throw new InvalidOperationException("Synthetic facts must not connect to a database.");
    }
}
