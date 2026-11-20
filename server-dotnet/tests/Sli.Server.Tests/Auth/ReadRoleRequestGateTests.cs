using System.Net;
using System.Text.Json;
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
using Sli.Server.Auth.Administration.ApiKeys;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;
using Xunit;

namespace Sli.Server.Tests.Auth;

public sealed class ReadRoleRequestGateTests
{
    // Independent snapshot of ddce909d's IT_ONLY_PATHS, including HTML and
    // paths owned by modules other than Operations (or not yet ported).
    public static TheoryData<string> OperatorPaths => new()
    {
        "/api/runtime/status", "/api/sources", "/api/domain-controllers", "/api/collector/health",
        "/api/system/health", "/api/storage/health", "/api/storage/lifecycle", "/api/db/status",
        "/api/diagnostics/overview", "/api/jobs", "/api/autocollection/status", "/api/logs/tail",
        "/reports/collector-health.html", "/reports/autocollection.html", "/reports/storage-health.html",
        "/reports/system-health.html", "/reports/db-status.html", "/reports/diagnostics.html",
        "/api/v1/operations/overview", "/api/v1/operations/plugins",
        "/api/v1/operations/administrative-activity", "/api/v1/source-packs", "/api/v1/source-adapters",
        "/api/jobs/1", "/api/jobs/future/detail"
    };

    public static TheoryData<string> AdminPaths => new()
    {
        "/admin", "/api/auth/users", "/api/auth/users/1", "/api/auth/users-future",
        "/api/auth/api-keys", "/api/auth/api-keys/1", "/api/auth/api-keys-future"
    };

    sealed class Auth : IPrincipalAuthenticator
    {
        public int Calls;
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext context, CancellationToken ct)
        {
            Calls++;
            string role = context.Request.Headers["X-Test-Role"].ToString();
            return ValueTask.FromResult(role.Length == 0 ? AuthenticationResult.Denied(401, "authentication_required")
                : AuthenticationResult.Success(new("session", 1, role)));
        }
    }

    sealed class Facts : IAccessFactsRepository
    {
        public int Reads;
        public bool Allow = true;
        public Task<AccessFacts> LoadAsync(Principal principal, CancellationToken ct)
        {
            Reads++;
            static JsonElement J(string value) => JsonDocument.Parse(value).RootElement.Clone();
            // A user-assigned package deliberately gives viewer the operational
            // capabilities too: capabilities must never substitute for a role.
            return Task.FromResult(new AccessFacts(false, principal.Role,
                Allow ? [J("""{"package_key":"test-operations","effect":"allow","source_kind":"user"}""")] : [],
                new[] { "operations.view", "administrative.activity.view", "access.manage" }
                    .Select(key => JsonSerializer.SerializeToElement(new { package_key = "test-operations", capability_key = key })).ToArray(),
                [], [], [], [], []));
        }
    }

    sealed class App(IHost host, Auth auth, Facts facts) : IDisposable
    {
        public HttpClient Client { get; } = host.GetTestClient();
        public Auth Auth => auth;
        public Facts Facts => facts;
        public void Dispose() { Client.Dispose(); host.Dispose(); }
    }

    static async Task<App> Start(bool authRequired = true, bool administration = false, bool secureTransport = false)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Sli:AuthRequired"] = authRequired ? "1" : "0", ["Sli:AllowUnauthenticated"] = authRequired ? "0" : "1",
            ["Sli:TrustedProxies"] = secureTransport ? "192.0.2.1/32" : ""
        }).Build();
        var auth = new Auth(); var facts = new Facts();
        var host = await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(services =>
        {
            services.AddRouting(); services.AddLogging(); services.AddSingleton<IConfiguration>(config);
            services.AddSingleton(new AuthRequestPolicy(config)); services.AddSingleton(new TransportGate(config));
            services.AddSingleton<IPrincipalAuthenticator>(auth); services.AddSingleton<IAccessFactsRepository>(facts);
            services.AddSingleton<ICapabilityComposer, CapabilityComposer>();
        }).Configure(app =>
        {
            app.UseRouting(); app.UseReadRoleRequestGate();
            if (administration) app.UseEndpoints(endpoints =>
            {
                endpoints.MapUserAdministrationEndpoints(); endpoints.MapApiKeyAdministrationEndpoints();
            });
            else app.UseEndpoints(endpoints => endpoints.MapMethods("/{**path}", ["GET", "HEAD", "POST"], async context =>
            {
                // This independently registered future handler has no role gate.
                // The application middleware must protect it before capability work.
                var access = await facts.LoadAsync(new("session", 1, context.Request.Headers["X-Test-Role"].ToString()), context.RequestAborted);
                string capability = context.Request.Path.Value!.Contains("administrative-activity") ? "administrative.activity.view" : "operations.view";
                var decision = new CapabilityComposer().Compose(access).Decide(capability);
                if (!decision.Allowed)
                    await DomainHttp.WriteAsync(context, new { error = decision.Reason, required_capability = capability }, 403, context.RequestAborted);
                else context.Response.StatusCode = 204;
            }));
        })).StartAsync(TestContext.Current.CancellationToken);
        return new(host, auth, facts);
    }

    static async Task<HttpResponseMessage> Request(App app, string path, string? role, string method = "GET")
    {
        using var request = new HttpRequestMessage(new HttpMethod(method), path);
        if (role is not null) request.Headers.Add("X-Test-Role", role);
        return await app.Client.SendAsync(request, TestContext.Current.CancellationToken);
    }

    static async Task Error(HttpResponseMessage response, HttpStatusCode status, string code)
    {
        Assert.Equal(status, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.Equal(code, json.RootElement.GetProperty("error").GetString());
        if (code == "insufficient_permissions") Assert.Single(json.RootElement.EnumerateObject());
    }

    [Theory] [MemberData(nameof(OperatorPaths))]
    public async Task EveryOperationalPathChecksAuthenticationThenRoleThenCapability(string path)
    {
        using var app = await Start();
        using (var anonymous = await Request(app, path, null)) await Error(anonymous, HttpStatusCode.Unauthorized, "authentication_required");
        using (var viewer = await Request(app, path + "?ignored=1", "viewer")) await Error(viewer, HttpStatusCode.Forbidden, "insufficient_permissions");
        Assert.Equal(0, app.Facts.Reads);
        foreach (string role in new[] { "operator", "admin" })
        {
            using var allowed = await Request(app, path, role);
            Assert.Equal(HttpStatusCode.NoContent, allowed.StatusCode);
        }
        app.Facts.Allow = false;
        using (var viewer = await Request(app, path, "viewer")) await Error(viewer, HttpStatusCode.Forbidden, "insufficient_permissions");
        Assert.Equal(2, app.Facts.Reads);
        using var denied = await Request(app, path, "operator");
        await Error(denied, HttpStatusCode.Forbidden, "insufficient_capability");
        Assert.Equal(3, app.Facts.Reads);
    }

    [Theory] [MemberData(nameof(AdminPaths))]
    public async Task AdministrativeReadsStillRequireAdmin(string path)
    {
        using var app = await Start();
        using (var anonymous = await Request(app, path, null)) await Error(anonymous, HttpStatusCode.Unauthorized, "authentication_required");
        foreach (string role in new[] { "viewer", "operator", "unknown" })
        {
            using var denied = await Request(app, path, role);
            await Error(denied, HttpStatusCode.Forbidden, "insufficient_permissions");
        }
        Assert.Equal(0, app.Facts.Reads);
        using var admin = await Request(app, path, "admin");
        Assert.Equal(HttpStatusCode.NoContent, admin.StatusCode);
    }

    [Theory] [InlineData("/api/auth/users", "GET")] [InlineData("/api/auth/api-keys", "GET")]
    [InlineData("/api/auth/users", "POST")] [InlineData("/api/auth/api-keys", "POST")]
    public async Task ExistingAdministrationHandlersRetainRoleAndCapabilityChecks(string path, string method)
    {
        using var app = await Start(administration: true); app.Facts.Allow = false;
        using (var anonymous = await Request(app, path, null, method)) await Error(anonymous, HttpStatusCode.Unauthorized, "authentication_required");
        foreach (string role in new[] { "viewer", "operator" })
        {
            using var denied = await Request(app, path, role, method);
            await Error(denied, HttpStatusCode.Forbidden, "insufficient_permissions");
        }
        Assert.Equal(0, app.Facts.Reads);
        using var admin = await Request(app, path, "admin", method);
        await Error(admin, HttpStatusCode.Forbidden, "insufficient_capability");
        Assert.Equal(1, app.Facts.Reads);
    }

    [Theory] [InlineData("/API/LOGS/TAIL/")] [InlineData("/api/jobs/next/detail/")]
    [InlineData("/reports/DIAGNOSTICS.html/")]
    public async Task RoutingAliasesCannotBypassRole(string path)
    {
        using var app = await Start();
        using var response = await Request(app, path, "viewer");
        await Error(response, HttpStatusCode.Forbidden, "insufficient_permissions");
        Assert.Equal(0, app.Facts.Reads);
    }

    [Theory] [InlineData("/api/health/details")] [InlineData("/api/jobs-extra")]
    [InlineData("/api/v1/operations/sources/DC1")] [InlineData("/api/v1/source-packs/next")]
    [InlineData("/api/auth/me")] [InlineData("/api/auth/login")] [InlineData("/api/auth/logout")]
    public async Task OtherPathsKeepTheirExistingEndpointPolicy(string path)
    {
        using var app = await Start(); using var response = await Request(app, path, "viewer");
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode); Assert.Equal(0, app.Auth.Calls);
    }

    [Fact]
    public async Task ExplicitUnauthenticatedModeStillUsesEndpointCapabilities()
    {
        using var app = await Start(authRequired: false); app.Facts.Allow = false;
        using var response = await Request(app, "/api/logs/tail", null);
        await Error(response, HttpStatusCode.Forbidden, "insufficient_capability"); Assert.Equal(0, app.Auth.Calls);
    }

    [Fact]
    public async Task TransportRestrictionStillPrecedesAuthentication()
    {
        using var app = await Start(secureTransport: true);
        using var response = await Request(app, "/api/logs/tail", null);
        await Error(response, HttpStatusCode.Forbidden, "secure_transport_required");
        Assert.Equal(0, app.Auth.Calls); Assert.Equal(0, app.Facts.Reads);
    }

    [Fact]
    public async Task HeadCannotReadProtectedRoutesAsViewer()
    {
        using var app = await Start(); using var response = await Request(app, "/api/logs/tail", "viewer", "HEAD");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); Assert.Equal(0, app.Facts.Reads);
    }
}
