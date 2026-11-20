using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Infrastructure;
using Xunit;

namespace Sli.Server.Tests.Access;

public sealed class ReportDomainScopeBoundaryTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task ActualServiceDeduplicatesOneReportAt100(bool generic, bool overlap)
    {
        var connections = new RefusingConnections();
        var service = Service(Facts(generic, overlap ? 50 : 61, overlap ? 51 : 40), connections);

        var result = await service.EvaluateAsync(new("session", 1, "viewer"), TestContext.Current.CancellationToken);

        Assert.True(result.CapabilityAllowed);
        Assert.Equal(DomainGrantKind.Scoped, result.Grant.Kind);
        Assert.Equal(Enumerable.Range(1, 100).Select(id => (long)id), result.Grant.DomainIds.Order());
        Assert.Equal(0, connections.Calls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ActualServiceKeepsSeparateReportUnionsAbove100(bool generic)
    {
        var connections = new RefusingConnections();
        var service = Service(Facts(generic, 61, 41, separateReports: true), connections);

        var result = await service.EvaluateAsync(new("session", 1, "viewer"), TestContext.Current.CancellationToken);

        Assert.True(result.CapabilityAllowed);
        Assert.Equal(DomainGrantKind.Scoped, result.Grant.Kind);
        Assert.Equal(Enumerable.Range(1, 101).Select(id => (long)id), result.Grant.DomainIds.Order());
        Assert.Equal(0, connections.Calls);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task ActualService101ThrowsTypedFailureAndKestrelReturnsExact400(bool generic, bool overlap)
    {
        var ct = TestContext.Current.CancellationToken;
        var connections = new RefusingConnections();
        var facts = Facts(generic, overlap ? 50 : 61, overlap ? 52 : 41);
        var error = await Assert.ThrowsAsync<DomainScopeCompositionException>(() =>
            Service(facts, connections).EvaluateAsync(new("session", 1, "viewer"), ct));
        Assert.Equal("invalid_scope_dimension", error.Message);

        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(Sli.Server.Tests.Domains.SafeTestEnvironment.ConfigureApiHost).WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sli:AuthRequired"] = "1", ["Sli:AllowUnauthenticated"] = "1", ["Sli:OwnerSetup"] = "0",
                ["Sli:AuthAllowInsecureHttp"] = "1", ["Sli:TrustedProxies"] = "",
                ["ConnectionStrings:Sli"] = "Host=127.0.0.1;Port=1;Database=synthetic;Username=synthetic"
            }));
            builder.ConfigureServices(services =>
            {
                var reconciliation = services.Single(d => d.ServiceType == typeof(Microsoft.Extensions.Hosting.IHostedService)
                    && d.ImplementationType == typeof(Sli.Server.Agents.Registry.AgentRegistrationReconciliation));
                services.Remove(reconciliation);
                services.RemoveAll<IPrincipalAuthenticator>();
                services.AddSingleton<IPrincipalAuthenticator, Authentication>();
                services.RemoveAll<IPostgresConnectionFactory>();
                services.AddSingleton<IPostgresConnectionFactory>(connections);
                services.RemoveAll<IAccessFactsRepository>();
                services.AddSingleton<IAccessFactsRepository>(new SyntheticFacts(facts));
                services.RemoveAll<IReportCatalogProvider>();
                services.AddSingleton<IReportCatalogProvider>(Catalog());
            });
        });
        factory.UseKestrel(options => options.Listen(IPAddress.Loopback, 0));
        using var client = factory.CreateClient();
        using var response = await client.GetAsync("/api/v1/domains", ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        byte[] expected = Encoding.UTF8.GetBytes("{\n  \"error\": \"domain_parameters_invalid\"\n}");
        Assert.Equal(expected, await response.Content.ReadAsByteArrayAsync(ct));
        Assert.Equal((long)expected.Length, response.Content.Headers.ContentLength);
        Assert.Equal("application/json; charset=utf-8", response.Content.Headers.ContentType!.ToString());
        Assert.Equal(0, connections.Calls);
    }

    private static ReportRuleCatalog Catalog() => new(new PluginGenerationReader(null));
    private static DomainAccessService Service(AccessFacts facts, RefusingConnections connections) =>
        new(connections, Catalog(), new SyntheticFacts(facts));

    // Synthetic authority inputs, not precomputed access decisions. The production
    // capability composer, report eligibility, catalog and resolver execute unchanged.
    private static AccessFacts Facts(bool generic, int secondStart, int secondCount, bool separateReports = false)
    {
        string[] fields = ["identity_basic", "security", "technical"];
        string[] keys = separateReports ? ["ad.state", "ad.users.v2"] : ["ad.state"];
        JsonElement Assignment(string key, int start, int count)
        {
            object scope = generic
                ? new { mode = "restricted", clauses = new[] { new { collection_scope_ids = Enumerable.Range(start, count).Select(id => $"ad-domain:{id}").ToArray() } } }
                : new { kind = "domain", ids = Enumerable.Range(start, count).ToArray() };
            return JsonSerializer.SerializeToElement(new { report_key = key, effect = "allow", scope_json = scope,
                field_categories = fields, allowed_actions = new[] { "view" } });
        }
        return new(false, "viewer", [], [],
            new[] { "workspace.view", "field.identity_basic", "field.security", "field.technical" }
                .Select(key => JsonSerializer.SerializeToElement(new { capability_key = key, effect = "allow", scope_json = new { kind = "all" } })).ToArray(),
            [], [], [Assignment(keys[0], 1, 60), Assignment(keys[^1], secondStart, secondCount)],
            keys.Select(key => JsonSerializer.SerializeToElement(new { report_key = key, version = 1, dataset_version = 1,
                definition_json = new { field_categories = fields, actions = new[] { "view" } },
                fields_json = fields.Select(category => new { category }).ToArray(), actions_json = new[] { "view" } })).ToArray());
    }

    private sealed class SyntheticFacts(AccessFacts facts) : IAccessFactsRepository
    {
        public Task<AccessFacts> LoadAsync(Principal principal, CancellationToken ct) => Task.FromResult(facts);
    }

    private sealed class RefusingConnections : IPostgresConnectionFactory
    {
        public int Calls { get; private set; }
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
        {
            Calls++;
            throw new InvalidOperationException("Scope validation must finish before reading domain rows.");
        }
    }

    private sealed class Authentication : IPrincipalAuthenticator
    {
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext context, CancellationToken ct) =>
            ValueTask.FromResult(AuthenticationResult.Success(new("session", 1, "viewer")));
    }
}
