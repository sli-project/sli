using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Infrastructure;
using Sli.Server.Investigations;
using Sli.Server.Storage.EventReports;
using Xunit;

namespace Sli.Server.Tests.Reporting;

// Observable dispatcher contracts from test_http_server_route_equivalence.py.
// Keep Program's actual route registrations, middleware and access composers.
public sealed class HttpServerRouteEquivalenceTests
{
    sealed class Authentication : IPrincipalAuthenticator
    {
        public bool LoggedIn = true;
        public string Role = "admin";
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext context, CancellationToken ct) =>
            ValueTask.FromResult(LoggedIn ? AuthenticationResult.Success(new("session", 1, Role)) :
                AuthenticationResult.Denied(401, "authentication_required"));
    }

    sealed class Facts : IAccessFactsRepository
    {
        public int Reads;
        public bool Fail;
        public AccessFacts Value = new(false, "admin", [], [], [], [], [], [], []);
        public Task<AccessFacts> LoadAsync(Principal principal, CancellationToken ct)
        {
            Reads++;
            if (Fail) throw new InvalidOperationException("synthetic-private-domain-error");
            return Task.FromResult(Value);
        }
    }

    sealed class Storage : IPostgresConnectionFactory, IEventReadService
    {
        public int DatabaseReads, ResourceReads, PayloadReads;
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
        { DatabaseReads++; throw new InvalidOperationException("Unexpected database access"); }
        public Task<IReadOnlyList<AccessResource>> ResourcesAsync(long id, CancellationToken ct)
        {
            Assert.Equal(99, id);
            ResourceReads++;
            return Task.FromResult<IReadOnlyList<AccessResource>>([new("server", 9)]);
        }
        public Task<Dictionary<long, JsonObject>> DetailsAsync(long[] ids, bool exact, Func<long, CancellationToken, Task<bool>> admitted, CancellationToken ct)
        { PayloadReads++; throw new InvalidOperationException("Denied event must not be hydrated"); }
        public Task<JsonObject> RelationsAsync(long id, Func<long, CancellationToken, Task<bool>> admitted, CancellationToken ct)
        { PayloadReads++; throw new InvalidOperationException("Denied event must not be correlated"); }
    }

    sealed class Fixture : IDisposable
    {
        public readonly Authentication Auth = new();
        public readonly Facts Facts = new();
        public readonly Storage Storage = new();
        readonly WebApplicationFactory<Program> host;
        public readonly HttpClient Client;

        public Fixture(bool authRequired = true)
        {
            host = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
            {
                builder.ConfigureAppConfiguration((_, config) =>
                {
                    config.Sources.Clear();
                    config.AddInMemoryCollection(new Dictionary<string, string?>
                    {
                        ["Sli:AuthRequired"] = authRequired ? "1" : "0",
                        ["Sli:AllowUnauthenticated"] = "1", ["Sli:OwnerSetup"] = "0",
                        ["Sli:AuthAllowInsecureHttp"] = "1", ["Sli:TrustedProxies"] = "",
                        ["Sli:AgentMtlsCaFile"] = "", ["Sli:AgentUpdateTrustFile"] = "",
                        ["Sli:OperatorToken"] = "", ["urls"] = "http://localhost:5000"
                    });
                });
                builder.ConfigureTestServices(services =>
                {
                    // No workers, sockets, database or deployment configuration.
                    services.RemoveAll<IHostedService>();
                    services.RemoveAll<IPrincipalAuthenticator>();
                    services.AddSingleton<IPrincipalAuthenticator>(Auth);
                    services.RemoveAll<IAccessFactsRepository>();
                    services.AddSingleton<IAccessFactsRepository>(Facts);
                    services.RemoveAll<IPostgresConnectionFactory>();
                    services.AddSingleton<IPostgresConnectionFactory>(Storage);
                    services.RemoveAll<IEventReadService>();
                    services.AddSingleton<IEventReadService>(Storage);
                });
            });
            Client = host.CreateClient(new WebApplicationFactoryClientOptions
            { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = false });
        }
        public void AssertNoDataRead()
        {
            Assert.Equal(0, Storage.DatabaseReads);
            Assert.Equal(0, Storage.ResourceReads);
            Assert.Equal(0, Storage.PayloadReads);
        }
        public IServiceScope CreateScope() => host.Services.CreateScope();
        public void Dispose() { Client.Dispose(); host.Dispose(); }
    }

    static async Task<JsonElement> Body(HttpResponseMessage response) =>
        JsonSerializer.Deserialize<JsonElement>(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

    [Theory]
    [InlineData("GET", "/some/totally/unknown/path", 404, "not_found")]
    [InlineData("GET", "/reports/totally-unknown-page.html", 403, "report_artifact_unclassified")]
    public async Task UnknownPathsCannotReachDomainStorage(string method, string path, int status, string error)
    {
        using var f = new Fixture(authRequired: false);
        using var response = await f.Client.SendAsync(new(new HttpMethod(method), path), TestContext.Current.CancellationToken);
        Assert.Equal(status, (int)response.StatusCode);
        var body = await Body(response);
        Assert.Single(body.EnumerateObject()); Assert.Equal(error, body.GetProperty("error").GetString());
        Assert.Equal(0, f.Facts.Reads); f.AssertNoDataRead();
    }

    [Theory]
    [InlineData("")]
    [InlineData("?legacy=1")]
    [InlineData("?legacy=1&limit=invalid")]
    public async Task FindingsBookmarkRedirectPrecedesLegacyCatchAllAndDataReads(string query)
    {
        using var f = new Fixture();
        using var response = await f.Client.GetAsync("/reports/findings.html" + query, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal("/app/scenarios", response.Headers.Location?.OriginalString);
        Assert.Equal(0, f.Facts.Reads); f.AssertNoDataRead();
    }

    [Theory]
    [InlineData(false, "admin", "/login?next=%2Freports%2Ffindings.html%3Flegacy%3D1")]
    [InlineData(true, "disabled", "/")]
    public async Task FindingsRedirectRetainsBrowserAuthenticationAndRoleGates(bool loggedIn, string role, string target)
    {
        using var f = new Fixture(); f.Auth.LoggedIn = loggedIn; f.Auth.Role = role;
        using var response = await f.Client.GetAsync("/reports/findings.html?legacy=1", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal(target, response.Headers.Location?.OriginalString);
        Assert.Equal(0, f.Facts.Reads); f.AssertNoDataRead();
    }

    [Theory]
    [InlineData("GET", "/api/auth/users", "authentication_required", null)]
    [InlineData("GET", "/api/v1/investigations/1", "report_not_assigned", null)]
    [InlineData("GET", "/api/v1/objects", "insufficient_capability", "objects.view")]
    public async Task SensitiveRoutesDenyBeforeReadingOrMutatingData(string method, string path, string error, string? capability)
    {
        using var f = new Fixture();
        if (path == "/api/auth/users") f.Auth.LoggedIn = false;
        using var response = await f.Client.SendAsync(new(new HttpMethod(method), path), TestContext.Current.CancellationToken);
        Assert.Equal(path == "/api/auth/users" ? 401 : 403, (int)response.StatusCode);
        var body = await Body(response); Assert.Equal(error, body.GetProperty("error").GetString());
        if (capability is not null) Assert.Equal(capability, body.GetProperty("required_capability").GetString());
        f.AssertNoDataRead();
    }

    [Fact]
    public async Task EventScopedInvestigationDenialIsHiddenBeforeWorkspaceRead()
    {
        using var f = new Fixture();
        static JsonElement J(string s) => JsonSerializer.Deserialize<JsonElement>(s);
        f.Facts.Value = new(false, "admin", [], [],
            [J("""{"capability_key":"investigations.view","effect":"allow","scope_json":{"kind":"all"}}""")], [], [],
            [J("""{"report_key":"investigations.workspace","effect":"allow","allowed_actions":["view"],"field_categories":["security"],"scope_json":{"kind":"server","ids":[7]}}""")],
            [J("""{"report_key":"investigations.workspace","version":1,"dataset_version":1,"definition_json":{"actions":["view"]},"actions_json":["view"],"fields_json":[{"category":"security"}]}""")]);
        const string path = "/api/v1/investigations", query = "?event_db_id=99";
        using var response = await f.Client.GetAsync(path + query, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        var disabled = await Body(response);
        Assert.Equal("module_disabled", disabled.GetProperty("error").GetString());
        Assert.Equal("disabled", disabled.GetProperty("state").GetString());
        f.AssertNoDataRead();

        // S6 no longer routes to the workspace reader (7a0cb3264).
        // Check the retained handler's resource denial with the same scoped facts.
        using var scope = f.CreateScope();
        using var payload = new MemoryStream();
        var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider, RequestAborted = TestContext.Current.CancellationToken };
        context.Request.Method = HttpMethods.Get;
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("localhost");
        context.Request.Path = path;
        context.Request.QueryString = new QueryString(query);
        context.Response.Body = payload;
        await InvestigationWorkspaceEndpoints.HandleAsync(context);
        Assert.Equal(StatusCodes.Status404NotFound, context.Response.StatusCode);
        var body = JsonSerializer.Deserialize<JsonElement>(payload.ToArray());
        Assert.Equal(2, body.EnumerateObject().Count());
        Assert.Equal("not_found", body.GetProperty("error").GetString());
        Assert.Equal("Investigation resource was not found", body.GetProperty("message").GetString());
        Assert.Equal(1, f.Storage.ResourceReads); Assert.Equal(0, f.Storage.PayloadReads); Assert.Equal(0, f.Storage.DatabaseReads);
    }

    [Theory]
    [InlineData("GET", "/api/v1/events")]
    [InlineData("POST", "/api/jobs/collect")]
    public async Task UnhandledDomainExceptionProducesSafeCorrelated500(string method, string path)
    {
        using var f = new Fixture(); f.Facts.Fail = true;
        using var response = await f.Client.SendAsync(new(new HttpMethod(method), path), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        var body = await Body(response);
        Assert.Equal(new[] { "error", "internal_error_id" }, body.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal));
        Assert.Equal("internal_server_error", body.GetProperty("error").GetString());
        Assert.True(Guid.TryParse(body.GetProperty("internal_error_id").GetString(), out var id) && id != Guid.Empty);
        Assert.DoesNotContain("synthetic-private-domain-error", body.GetRawText());
        Assert.Equal(1, f.Facts.Reads); f.AssertNoDataRead();
    }
}
