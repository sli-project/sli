using System.Net;
using System.Text;
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
using Sli.Server.Legacy;
using Xunit;

namespace Sli.Server.Tests.Legacy;

public sealed class LegacyJobEndpointTests
{
    private static JsonElement J(string text) => JsonDocument.Parse(text).RootElement.Clone();
    private sealed class Authentication : IPrincipalAuthenticator
    {
        public Principal? Principal = new("session", 1, "operator", "operator");
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext c, CancellationToken ct) =>
            ValueTask.FromResult(Principal is null ? AuthenticationResult.Denied(401, "authentication_required") : AuthenticationResult.Success(Principal));
    }
    private sealed class Facts : IAccessFactsRepository
    {
        public string Effect = "allow";
        public string Scope = "{\"kind\":\"all\"}";
        public bool Owner;
        public Task<AccessFacts> LoadAsync(Principal p, CancellationToken ct) => Task.FromResult(new AccessFacts(Owner, p.Role, [], [],
            [J("{\"capability_key\":\"operations.view\",\"effect\":\"" + Effect + "\",\"scope_json\":" + Scope + "}")], [], [], [], []));
    }
    private sealed class Jobs : ILegacyJobs
    {
        public int Calls;
        public bool Collect;
        public LegacyJobInput? Input;
        public Task<JsonObject> CreateAsync(bool collect, LegacyJobInput input, CancellationToken ct)
        { Calls++; Collect = collect; Input = input; return Task.FromResult(new JsonObject { ["id"] = 7, ["status"] = "queued" }); }
        public Task<JsonObject> CreateExternalAsync(LegacyJobInput input, CancellationToken ct) => throw new InvalidOperationException("unexpected external worker");
    }
    private sealed class Fixture : IDisposable
    {
        public readonly Authentication Authentication = new();
        public readonly Facts Facts = new();
        public readonly Jobs Jobs = new();
        public readonly ServiceProvider Provider;
        public readonly DefaultHttpContext Context;
        public Fixture(string body, bool collect, Dictionary<string,string?>? extra = null)
        {
            var values = new Dictionary<string,string?> { ["Sli:AuthRequired"] = "true" };
            foreach (var pair in extra ?? []) values[pair.Key] = pair.Value;
            var config = new ConfigurationBuilder().AddInMemoryCollection(values).Build();
            Provider = new ServiceCollection().AddLogging().AddSingleton<IConfiguration>(config)
                .AddSingleton(new AuthRequestPolicy(config)).AddSingleton(new TransportGate(config))
                .AddSingleton<IPrincipalAuthenticator>(Authentication).AddSingleton<IAccessFactsRepository>(Facts)
                .AddSingleton<ILegacyJobs>(Jobs).BuildServiceProvider();
            Context = new DefaultHttpContext { RequestServices = Provider };
            Context.Request.Method = "POST"; Context.Request.Scheme = "https"; Context.Request.Host = new("example.test");
            Context.Request.Path = collect ? "/api/jobs/collect" : "/api/jobs/analyze";
            Context.Request.ContentType = "application/json"; Context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(body));
            Context.Request.ContentLength = Context.Request.Body.Length; Context.Response.Body = new MemoryStream();
        }
        public JsonElement Response => J(Encoding.UTF8.GetString(((MemoryStream)Context.Response.Body).ToArray()));
        public void Dispose() { Provider.Dispose(); Context.Request.Body.Dispose(); Context.Response.Body.Dispose(); }
    }

    [Theory]
    [InlineData(true)] [InlineData(false)]
    public async Task OperatorSuccessPreservesDefaultsAndJobResponse(bool collect)
    {
        using var f = new Fixture("{}", collect);
        await LegacyJobEndpoints.HandleAsync(f.Context, collect);
        Assert.Equal(503, f.Context.Response.StatusCode);
        Assert.Equal("module_disabled", f.Response.GetProperty("error").GetString());
        Assert.Equal(0, f.Jobs.Calls);
    }
    [Theory]
    [InlineData(true)] [InlineData(false)]
    public async Task AdministratorExplicitTargetAndPythonCoercions(bool collect)
    {
        using var f = new Fixture("{}", collect);
        await LegacyJobEndpoints.HandleAsync(f.Context, collect);
        Assert.Equal(503, f.Context.Response.StatusCode);
        Assert.Equal("module_disabled", f.Response.GetProperty("error").GetString());
        Assert.Equal(0, f.Jobs.Calls);
    }
    [Theory]
    [InlineData(true)] [InlineData(false)]
    public async Task ViewerCannotMutateEvenWithCapabilityOrOwnerFlag(bool collect)
    {
        using var f = new Fixture("invalid", collect); f.Authentication.Principal = new("session", 1, "viewer"); f.Facts.Owner = true;
        await LegacyJobEndpoints.HandleAsync(f.Context, collect);
        Assert.Equal(403, f.Context.Response.StatusCode); Assert.Equal("insufficient_permissions", f.Response.GetProperty("error").GetString());
        Assert.Equal(0, f.Context.Request.Body.Position); Assert.Equal(0, f.Jobs.Calls);
    }
    [Theory]
    [InlineData(true)] [InlineData(false)]
    public async Task CapabilityDenialPrecedesBodyParsing(bool collect)
    {
        using var f = new Fixture("invalid", collect); f.Facts.Effect = "deny";
        await LegacyJobEndpoints.HandleAsync(f.Context, collect);
        Assert.Equal(403, f.Context.Response.StatusCode); Assert.Equal("explicit_deny", f.Response.GetProperty("error").GetString());
        Assert.Equal("operations.view", f.Response.GetProperty("required_capability").GetString());
        Assert.Equal(0, f.Context.Request.Body.Position); Assert.Equal(0, f.Jobs.Calls);
    }
    [Theory]
    [InlineData(true)] [InlineData(false)]
    public async Task ResourceOnlyOperationsGrantCannotRunGlobalJob(bool collect)
    {
        using var f = new Fixture("{}", collect); f.Facts.Scope = "{\"kind\":\"domain\",\"ids\":[1]}";
        await LegacyJobEndpoints.HandleAsync(f.Context, collect);
        Assert.Equal(403, f.Context.Response.StatusCode); Assert.Equal("resource_context_required", f.Response.GetProperty("error").GetString());
        Assert.Equal(0, f.Jobs.Calls);
    }
    [Theory]
    [InlineData(true)] [InlineData(false)]
    public async Task MissingAuthenticationReturns401(bool collect)
    {
        using var f = new Fixture("{}", collect); f.Authentication.Principal = null;
        await LegacyJobEndpoints.HandleAsync(f.Context, collect); Assert.Equal(401, f.Context.Response.StatusCode); Assert.Equal(0, f.Jobs.Calls);
    }
    [Theory]
    [InlineData(true)] [InlineData(false)]
    public async Task ReportKeyIsDeniedBeforeAnyBodyOrJob(bool collect)
    {
        using var f = new Fixture("{}", collect); f.Authentication.Principal = new("api_key", 1, "admin", ReportSubjectId: 2);
        await LegacyJobEndpoints.HandleAsync(f.Context, collect);
        Assert.Equal(403, f.Context.Response.StatusCode); Assert.Equal("report_key_route_denied", f.Response.GetProperty("error").GetString()); Assert.Equal(0, f.Jobs.Calls);
    }
    [Theory]
    [InlineData(true, "not json", "invalid_json")]
    [InlineData(false, "not json", "invalid_json")]
    [InlineData(true, "[]", "json_object_required")]
    [InlineData(false, "[]", "json_object_required")]
    [InlineData(false, "{\"server\":\"dc\\n.example.test\"}", "invalid_server")]
    public async Task BadInputDoesNotScheduleWork(bool collect, string body, string error)
    {
        using var f = new Fixture(body, collect);
        await LegacyJobEndpoints.HandleAsync(f.Context, collect);
        Assert.Equal(400, f.Context.Response.StatusCode); Assert.Equal(error, f.Response.GetProperty("error").GetString()); Assert.Equal(0, f.Jobs.Calls);
    }
    [Theory]
    [InlineData("{\"hours\":\"invalid\"}")]
    [InlineData("{\"max_events_per_channel\":\"invalid\"}")]
    public async Task InvalidIntegerMatchesReferenceDispatcher500(string body)
    {
        using var f = new Fixture(body,true);
        await LegacyJobEndpoints.HandleAsync(f.Context,true);
        Assert.Equal(500,f.Context.Response.StatusCode); Assert.Equal("internal_server_error",f.Response.GetProperty("error").GetString());
        Assert.True(f.Response.TryGetProperty("internal_error_id",out _)); Assert.Equal(0,f.Jobs.Calls);
    }
    [Theory]
    [InlineData(true)] [InlineData(false)]
    public async Task CrossOriginRejectedBeforeParsing(bool collect)
    {
        using var f = new Fixture("invalid", collect); f.Context.Request.Headers.Origin = "https://untrusted.example.test";
        await LegacyJobEndpoints.HandleAsync(f.Context, collect); Assert.Equal(403, f.Context.Response.StatusCode);
        Assert.Equal("cross_origin_request_rejected", f.Response.GetProperty("error").GetString()); Assert.Equal(0, f.Context.Request.Body.Position);
    }
    [Theory]
    [InlineData(true)] [InlineData(false)]
    public async Task OperatorTokenAppliesInExplicitUnauthenticatedMode(bool collect)
    {
        using var f = new Fixture("{}", collect, new() { ["Sli:AuthRequired"] = "false", ["Sli:AllowUnauthenticated"] = "true", ["Sli:OperatorToken"] = "test-only-operator-token" });
        await LegacyJobEndpoints.HandleAsync(f.Context, collect); Assert.Equal(401, f.Context.Response.StatusCode); Assert.Equal(0, f.Jobs.Calls);
        f.Context.Response.Body.SetLength(0); f.Context.Request.Headers["X-ADLog-Operator-Token"] = "test-only-operator-token";
        await LegacyJobEndpoints.HandleAsync(f.Context, collect); Assert.Equal(503, f.Context.Response.StatusCode); Assert.Equal(0, f.Jobs.Calls);
    }
    [Fact]
    public async Task BothRoutesAreRegisteredAndDoNotReach501Fallback()
    {
        using var f = new Fixture("{}", true);
        using var host = await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(s => {
            s.AddRouting(); s.AddLogging(); s.AddSingleton(f.Provider.GetRequiredService<IConfiguration>());
            s.AddSingleton(f.Provider.GetRequiredService<AuthRequestPolicy>()); s.AddSingleton(f.Provider.GetRequiredService<TransportGate>());
            s.AddSingleton<IPrincipalAuthenticator>(f.Authentication); s.AddSingleton<IAccessFactsRepository>(f.Facts); s.AddSingleton<ILegacyJobs>(f.Jobs);
        }).Configure(app => { app.UseRouting(); app.UseEndpoints(e => { e.MapLegacyJobs(); e.MapFallback(c => { c.Response.StatusCode = 501; return Task.CompletedTask; }); }); }))
            .StartAsync(TestContext.Current.CancellationToken);
        using var client = host.GetTestClient(); client.BaseAddress = new Uri("https://example.test");
        foreach (string path in new[] { "/api/jobs/collect", "/api/jobs/analyze" }) {
            using var response = await client.PostAsync(path, new StringContent("{}", Encoding.UTF8, "application/json"), TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        }
        Assert.Equal(0, f.Jobs.Calls);
    }
}
