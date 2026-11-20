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
using Xunit;

namespace Sli.Server.Tests.Compatibility;

public sealed class SystemHealthReportTests
{
    public static TheoryData<string> ReferenceCases
    {
        get
        {
            using var stream = typeof(SystemHealthReportTests).Assembly.GetManifestResourceStream(
                "Sli.Server.Tests.Compatibility.system-health-http-source.json")!;
            var data = new TheoryData<string>();
            foreach (var vector in JsonNode.Parse(stream)!.AsArray()) data.Add(vector!.ToJsonString());
            return data;
        }
    }

    sealed class Authentication(JsonNode input) : IPrincipalAuthenticator
    {
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext context, CancellationToken ct) =>
            ValueTask.FromResult(input["authenticated"]?.GetValue<bool>() != false
                ? AuthenticationResult.Success(new("session", 1, input["role"]?.ToString() ?? "operator"))
                : AuthenticationResult.Denied(401, "authentication_required"));
    }

    sealed class Facts(JsonNode input) : IAccessFactsRepository
    {
        public int Calls;
        public Task<AccessFacts> LoadAsync(Principal principal, CancellationToken ct)
        {
            Calls++;
            string grant = input["grant"]?.ToString() ?? "global";
            JsonElement[] policies = grant == "missing" ? [] : [JsonSerializer.SerializeToElement(new
            {
                capability_key = "operations.view", effect = grant == "deny" ? "deny" : "allow",
                scope_json = grant == "scoped" ? (object)new { kind = "domain", ids = new[] { 7 } } : new { kind = "all" }
            })];
            return Task.FromResult(new AccessFacts(false, principal.Role, [], [], policies, [], [], [], []));
        }
    }

    sealed class Reader : ILegacyHttpReader
    {
        public int Calls;
        public Task<JsonObject> ReadAsync(string path, LegacyQuery query, CancellationToken ct)
        {
            Calls++;
            throw new InvalidOperationException("The reference redirects before reading health data.");
        }
    }

    [Theory, MemberData(nameof(ReferenceCases))]
    public async Task HTTP_response_matches_Python_dispatcher(string vectorJson)
    {
        var vector = JsonNode.Parse(vectorJson)!;
        var input = vector["input"]!; var expected = vector["expected"]!;
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Sli:AuthRequired"] = (input["auth_required"]?.GetValue<bool>() != false).ToString(),
            ["Sli:AllowUnauthenticated"] = "true"
        }).Build();
        var facts = new Facts(input); var reader = new Reader();
        using var host = await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(services =>
        {
            services.AddRouting(); services.AddLogging(); services.AddSingleton<IConfiguration>(config);
            services.AddSingleton(new AuthRequestPolicy(config)); services.AddSingleton(new TransportGate(config));
            services.AddSingleton<IPrincipalAuthenticator>(new Authentication(input));
            services.AddSingleton<IAccessFactsRepository>(facts); services.AddSingleton<ILegacyHttpReader>(reader);
        }).Configure(app => { app.UseRouting(); app.UseEndpoints(routes => routes.MapLegacyHttp()); }))
            .StartAsync(TestContext.Current.CancellationToken);
        using var client = host.GetTestClient();
        using var response = await client.GetAsync(input["url"]!.ToString(), TestContext.Current.CancellationToken);
        Assert.Equal(expected["status"]!.GetValue<int>(), (int)response.StatusCode);
        Assert.Equal(expected["location"]?.ToString(), response.Headers.Location?.OriginalString);
        string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        if (expected["json"] is {} json)
        {
            Assert.Equal("application/json; charset=utf-8", response.Content.Headers.ContentType?.ToString());
            Assert.True(JsonNode.DeepEquals(json, JsonNode.Parse(body)), body);
        }
        else { Assert.Equal("", body); Assert.Null(response.Content.Headers.ContentType); }
        Assert.Equal(0, reader.Calls);
        bool auth = input["auth_required"]?.GetValue<bool>() != false;
        bool noFacts = auth && (input["authenticated"]?.GetValue<bool>() == false || input["role"]?.ToString() is "viewer" or "unknown");
        Assert.Equal(noFacts ? 0 : 1, facts.Calls);
    }
}
