using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Agents;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.FileAudit;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Infrastructure;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class AgentPolicyAccessTests
{
    public static IEnumerable<object[]> AdministrationVectors()
    {
        // tests/access/test_agent_policy_access.py: all nine routes and five
        // effective-authority cases. The coarse admin role grants nothing here.
        (string Method, string Path)[] routes = [
            ("GET", "/api/v1/admin/agents"),
            ("GET", "/api/v1/admin/agent-tokens"),
            ("POST", "/api/v1/admin/agents/modules"),
            ("POST", "/api/v1/admin/agents/rights-probe"),
            ("POST", "/api/v1/admin/agents/file-audit"),
            ("POST", "/api/v1/admin/agents/policy"),
            ("POST", "/api/v1/admin/agents/disable"),
            ("POST", "/api/v1/admin/agents/revoke"),
            ("POST", "/api/v1/admin/agent-tokens")
        ];
        foreach (var (method, path) in routes)
        {
            yield return [method, path, false, false, false, false, 401, "admin"];
            yield return [method, path, true, false, false, false, 403, "admin"];
            yield return [method, path, true, true, false, false, 200, "admin"];
            yield return [method, path, true, false, true, false, 200, "admin"];
            yield return [method, path, true, false, true, true, 403, "admin"];
            // Also guard against replacing effective access with a coarse admin gate.
            yield return [method, path, true, false, true, false, 200, "viewer"];
        }
    }

    [Theory]
    [MemberData(nameof(AdministrationVectors))]
    public async Task RealAdministrationRoutesUseEffectiveAuthorityBeforeExecution(
        string method, string path, bool authenticated, bool owner, bool manage, bool denied, int expected, string role)
    {
        var auth = new Authentication(authenticated, role);
        var facts = new Facts(owner, manage, denied, role);
        var database = new ExecutionBoundary();
        using var host = await Host(auth, facts, database);
        using var client = host.GetTestClient();
        using var request = new HttpRequestMessage(new HttpMethod(method), path);
        if (method == "POST") request.Content = new StringContent("{\"agent_id\":\"synthetic\"}", Encoding.UTF8, "application/json");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        using var json = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(TestContext.Current.CancellationToken));

        Assert.Equal(1, auth.Calls);
        Assert.Equal(authenticated ? 1 : 0, facts.Calls);
        Assert.Equal(expected == 200 ? 1 : 0, database.Opens);
        // Python substitutes _execute and only checks whether execution was
        // admitted for its "200" cases. Stop at the same boundary without a DB
        // or fabricated operation result; the real endpoint reports this failure.
        Assert.Equal(expected == 200 ? HttpStatusCode.ServiceUnavailable : (HttpStatusCode)expected, response.StatusCode);
        Assert.Equal(expected switch {
            401 => "authentication_required",
            403 when denied => "explicit_deny",
            403 => "insufficient_capability",
            _ => "agent_service_unavailable"
        }, json.RootElement.GetProperty("error").GetString());
        if (expected == 403) Assert.Equal("access.manage", json.RootElement.GetProperty("required_capability").GetString());
        Assert.True(response.Headers.CacheControl?.NoStore);
    }

    [Fact]
    public async Task PolicyReportIsRegisteredAndUsesAgentAuthenticationWithoutAmbientUserCapabilities()
    {
        var auth = new Authentication(false, "admin");
        var facts = new Facts(false, false, true, "admin");
        var database = new ExecutionBoundary();
        using var host = await Host(auth, facts, database);
        using var client = host.GetTestClient();
        using var response = await client.PostAsync("/api/v1/agent/policy-report", new StringContent("{}", Encoding.UTF8, "application/json"), TestContext.Current.CancellationToken);
        using var json = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(TestContext.Current.CancellationToken));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("agent_mtls_required", json.RootElement.GetProperty("error").GetString());
        Assert.False(json.RootElement.TryGetProperty("required_capability", out _));
        Assert.Equal(0, auth.Calls);
        Assert.Equal(0, facts.Calls);
        Assert.Equal(0, database.Opens);
    }

    private static async Task<IHost> Host(Authentication auth, Facts facts, ExecutionBoundary database)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            ["Sli:AuthRequired"] = "1", ["Sli:TrustedProxies"] = "", ["Sli:OwnerSetup"] = "0"
        }).Build();
        return await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(services =>
        {
            services.AddRouting(); services.AddLogging(); services.AddSingleton<IConfiguration>(config);
            services.AddSingleton(new TransportGate(config)); services.AddSingleton(new AuthRequestPolicy(config));
            services.AddSingleton<IPrincipalAuthenticator>(auth); services.AddSingleton<IAccessFactsRepository>(facts);
            services.AddSingleton<IPostgresConnectionFactory>(database);
            services.AddAgentControl(); services.AddAgentLifecycleControl(); services.AddFileAuditControl();
            services.AddAgentClientControl();
        }).Configure(app => {
            // TestServer leaves RawTarget empty; Kestrel supplies it on the wire.
            app.Use((context, next) => {
                context.Features.Get<IHttpRequestFeature>()!.RawTarget = context.Request.Path.ToUriComponent() + context.Request.QueryString;
                return next(context);
            });
            app.UseRouting(); app.UseEndpoints(routes => {
                routes.MapAgentControlEndpoints(); routes.MapAgentLifecycleControlEndpoints();
                routes.MapFileAuditControlEndpoints(); routes.MapAgentClientControlEndpoints();
            });
        })).StartAsync(TestContext.Current.CancellationToken);
    }

    private sealed class Authentication(bool authenticated, string role) : IPrincipalAuthenticator
    {
        internal int Calls;
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext context, CancellationToken ct)
        {
            Calls++;
            return ValueTask.FromResult(authenticated ? AuthenticationResult.Success(new Principal("session", 1, role))
                : AuthenticationResult.Denied(401, "authentication_required"));
        }
    }

    private sealed class Facts(bool owner, bool manage, bool denied, string role) : IAccessFactsRepository
    {
        internal int Calls;
        public Task<AccessFacts> LoadAsync(Principal principal, CancellationToken ct)
        {
            Calls++;
            List<JsonElement> grants = [];
            if (manage) grants.Add(JsonSerializer.SerializeToElement(new { capability_key = "access.manage", effect = "allow", scope_json = new { kind = "all" } }));
            if (denied) grants.Add(JsonSerializer.SerializeToElement(new { capability_key = "access.manage", effect = "deny", scope_json = new { kind = "all" } }));
            return Task.FromResult(new AccessFacts(owner, role, [], [], grants, [], [], [], []));
        }
    }

    private sealed class ExecutionBoundary : IPostgresConnectionFactory
    {
        internal int Opens;
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
        {
            Opens++;
            throw new InvalidOperationException("Synthetic stop after real administrative authorization");
        }
    }
}
