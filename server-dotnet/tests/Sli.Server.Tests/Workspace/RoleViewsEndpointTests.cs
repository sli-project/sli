using System.Diagnostics;
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
using Sli.Server.Auth.Administration;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Compatibility;
using Sli.Server.Legacy;
using Sli.Server.Workspace;
using Xunit;

namespace Sli.Server.Tests.Workspace;

public sealed class RoleViewsEndpointTests
{
    static JsonArray Vectors()
    {
        using var stream = typeof(RoleViewsEndpointTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Workspace.role-views-reference.json")!;
        return JsonNode.Parse(stream)!.AsArray();
    }

    sealed class Authentication(JsonObject input) : IPrincipalAuthenticator
    {
        public int Calls;
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext context, CancellationToken ct)
        {
            Calls++;
            string? role = input.ContainsKey("role") ? input["role"]?.ToString() : "viewer";
            return ValueTask.FromResult(role is null ? AuthenticationResult.Denied(401, "authentication_required")
                : AuthenticationResult.Success(new("session", 1, role)));
        }
    }

    sealed class Facts(JsonObject input) : IAccessFactsRepository
    {
        public int Reads;
        public Task<AccessFacts> LoadAsync(Principal principal, CancellationToken ct)
        {
            Reads++;
            JsonElement[] direct = input["grant"]?.GetValue<bool>() == false ? [] : [JsonSerializer.SerializeToElement(new
            {
                capability_key = "workspace.view", effect = input["effect"]?.ToString() ?? "allow",
                scope_json = input["scope"]?.DeepClone() ?? new JsonObject { ["kind"] = "all" }
            })];
            return Task.FromResult(new AccessFacts(input["owner"]?.GetValue<bool>() == true, principal.Role, [], [], direct, [], [], [], []));
        }
    }

    sealed class ForbiddenRows : ILegacyRows
    {
        public int Calls;
        public Task<JsonArray> QueryAsync(string sql, IReadOnlyList<object> parameters, int timeoutMs, CancellationToken ct)
        { Calls++; throw new InvalidOperationException("unexpected_data_read"); }
        public Task<JsonArray> HistoryAsync(string sql, IReadOnlyDictionary<string, string> parameters, CancellationToken ct)
        { Calls++; throw new InvalidOperationException("unexpected_history_read"); }
        public Task<Dictionary<long, JsonObject>> HistoryEventsAsync(long[] ids, CancellationToken ct)
        { Calls++; throw new InvalidOperationException("unexpected_history_read"); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RegisteredGetPreservesSecurityAndReturnsCurrentCachedRoleViews(bool populated)
    {
        foreach (var vector in Vectors().OfType<JsonObject>())
        {
            var input = vector["input"]!.AsObject();
            bool authRequired = input["auth_required"]?.GetValue<bool>() != false;
            var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sli:AuthRequired"] = authRequired ? "1" : "0",
                ["Sli:AllowUnauthenticated"] = authRequired ? "0" : "1",
                ["Sli:TrustedProxies"] = "192.0.2.1/32"
            }).Build();
            var auth = new Authentication(input); var facts = new Facts(input); var rows = new ForbiddenRows();
            var cachedViews = populated
                ? JsonNode.Parse("""{"views":[{"title":"<script>fixture</script>"}],"summary":{"total_events":17}}""")!.AsObject()
                : new JsonObject { ["views"] = new JsonArray(), ["summary"] = new JsonObject { ["total_events"] = 0 } };
            var cache = new DashboardSnapshotCache {
                Payload = new JsonObject { ["status"] = "ok", ["diagnostics"] = new JsonObject(), ["role_views"] = cachedViews.DeepClone() },
                Created = Stopwatch.GetTimestamp()
            };
            using var host = await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(services =>
            {
                services.AddRouting(); services.AddLogging(); services.AddSingleton<IConfiguration>(config);
                services.AddSingleton(new TransportGate(config)); services.AddSingleton(new AuthRequestPolicy(config));
                services.AddSingleton<IPrincipalAuthenticator>(auth); services.AddSingleton<IAccessFactsRepository>(facts);
                services.AddSingleton(provider => new DashboardSnapshotReader(rows, null!, null!, new LegacySettings(config), cache, provider.GetRequiredService<IServiceScopeFactory>()));
                services.AddScoped<IWorkspaceCompatibilityReader>(provider => new WorkspaceCompatibilityReader(null!, config, null!, provider.GetRequiredService<DashboardSnapshotReader>(), null!));
            }).Configure(app =>
            {
                app.UseRouting(); app.UseReadRoleRequestGate(); app.UseEndpoints(endpoints => endpoints.MapWorkspaceCompatibility());
            })).StartAsync(TestContext.Current.CancellationToken);
            using var client = host.GetTestClient();
            string scheme = input["secure"]?.GetValue<bool>() == false ? "http" : "https";
            using var request = new HttpRequestMessage(HttpMethod.Get, scheme + "://sli.example.test/api/role-views" + input["query"]?.ToString());
            request.Headers.Accept.ParseAdd("text/html");
            using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
            var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
            bool allowed = vector["status"]!.GetValue<int>() == 500;
            int expectedStatus = allowed ? 200 : vector["status"]!.GetValue<int>();
            Assert.True((int)response.StatusCode == expectedStatus, input["name"] + ": expected " + expectedStatus + ", actual " + response.StatusCode);
            Assert.Equal("application/json", response.Content.Headers.ContentType!.MediaType);
            if (body.ContainsKey("internal_error_id"))
            {
                Assert.False(string.IsNullOrWhiteSpace(body["internal_error_id"]!.ToString()));
                body["internal_error_id"] = "reference-error-id";
            }
            Assert.True(JsonNode.DeepEquals(allowed ? cachedViews : vector["body"], body), input["name"] + ": " + body);
            Assert.Equal(vector["access_reads"]!.GetValue<int>(), facts.Reads);
            Assert.Equal(0, rows.Calls);
            Assert.Equal(authRequired && input["secure"]?.GetValue<bool>() != false ? 1 : 0, auth.Calls);
        }
    }
}
