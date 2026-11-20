using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Sli.Server.Reporting;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed class SliV4FixtureTests
{
    private static JsonObject Evaluate(string actor, DateOnly? today = null) => SliV4Fixture.Evaluate(
        JsonSerializer.SerializeToElement(new { actor, fixture = "sli-universal-prototype-v4" }), today ?? new DateOnly(2026, 11, 8));
    private static string[] Strings(JsonNode? array) => array!.AsArray().Select(v => v!.GetValue<string>()).ToArray();

    // tests/reporting/test_sli_v4_fixture.py: test_fixture_access_composition_is_server_evaluated
    [Fact]
    public void FixtureAccessCompositionIsServerEvaluated()
    {
        var alex = Evaluate("alex");
        Assert.Equal(new[] { "sec-operators", "ad-auditors" }, alex["packages"]!.AsArray().Select(p => p!["key"]!.GetValue<string>()));
        Assert.Equal(new[] { "privileged-accounts" }, Strings(alex["direct_reports"]));
        Assert.Equal(new[] { "ad-summary", "gpo-review", "privileged-accounts", "security-queue" }, Strings(alex["reports"]));
        Assert.True(alex["server_evaluated"]!.GetValue<bool>());
        Assert.Equal(new[] { "ad.attributes", "identity.basic", "pii.contact", "pii.hr" }, Strings(alex["fields"]));
        Assert.Equal(new[] { "OU=Users_KHV", "host5.example.invalid" }, Strings(alex["scopes"]));
        var privileged = alex["report_decisions"]!.AsArray().Single(d => d!["report"]!.GetValue<string>() == "privileged-accounts")!;
        Assert.True(privileged["allowed"]!.GetValue<bool>());
        var trace = Assert.Single(privileged["trace"]!.AsArray())!;
        Assert.Equal("direct", trace["source_type"]!.GetValue<string>());
        Assert.Equal("2026-12-31", trace["valid_until"]!.GetValue<string>());
        Assert.Equal("Распоряжение ИБ-128", trace["source"]!.GetValue<string>());
        Assert.All(alex["report_decisions"]!.AsArray(), decision =>
        {
            Assert.Equal(Strings(alex["scopes"]), Strings(decision!["scope"]));
            Assert.Equal(Strings(alex["fields"]), Strings(decision["fields"]));
            Assert.Equal(new[] { "view", "export" }, Strings(decision["actions"]));
        });
        Assert.Empty(alex["explicit_denies"]!.AsArray());
    }

    // tests/reporting/test_sli_v4_fixture.py: test_access_admin_has_no_implicit_ad_or_security_report
    [Fact]
    public void AccessAdminHasNoImplicitAdOrSecurityReport()
    {
        var admin = Evaluate("admin");
        Assert.Equal(new[] { "project-readiness", "technical-events" }, Strings(admin["reports"]));
        Assert.Contains("access.manage", Strings(admin["capabilities"]));
        Assert.DoesNotContain("ad-summary", Strings(admin["reports"]));
        Assert.DoesNotContain("security-queue", Strings(admin["reports"]));
        Assert.Empty(admin["direct_reports"]!.AsArray());
    }

    // tests/reporting/test_sli_v4_fixture.py: test_invalid_fixture_actor_fails_closed, plus malformed selectors.
    [Theory]
    [InlineData("""{"actor":"root","fixture":"sli-universal-prototype-v4"}""")]
    [InlineData("""{"actor":"alex","fixture":"other"}""")]
    [InlineData("""{"actor":"Alex","fixture":"sli-universal-prototype-v4"}""")]
    [InlineData("""{"fixture":"sli-universal-prototype-v4"}""")]
    [InlineData("""{"actor":null,"fixture":"sli-universal-prototype-v4"}""")]
    [InlineData("""{"actor":[],"fixture":"sli-universal-prototype-v4"}""")]
    [InlineData("""{"actor":"alex"}""")]
    [InlineData("{}")]
    public void InvalidFixtureActorFailsClosed(string payload)
    {
        using var document = JsonDocument.Parse(payload);
        var error = Assert.Throws<ArgumentException>(() => SliV4Fixture.Evaluate(document.RootElement));
        Assert.Equal("invalid_sli_v4_fixture_actor", error.Message);
    }

    [Theory]
    [InlineData("alex", "2026-12-31", true)]
    [InlineData("alex", "2027-01-01", false)]
    [InlineData("dmitry", "2026-09-30", true)]
    [InlineData("dmitry", "2026-10-01", false)]
    public void DirectGrantExpiryIsInclusiveAndKeepsDeclaredAssignment(string actor, string date, bool allowed)
    {
        var decision = Evaluate(actor, DateOnly.ParseExact(date, "yyyy-MM-dd"));
        Assert.Equal(allowed, Strings(decision["reports"]).Contains("privileged-accounts"));
        Assert.Equal(allowed, decision["report_decisions"]!.AsArray().Any(d => d!["report"]!.GetValue<string>() == "privileged-accounts"));
        Assert.Contains("privileged-accounts", Strings(decision["direct_reports"]));
        Assert.Contains("ad-summary", Strings(decision["reports"]));
    }

    [Fact]
    public void OperatorHasOnlyPackageGrantAndCannotExport()
    {
        var marina = Evaluate("marina");
        Assert.Equal(new[] { "security-queue" }, Strings(marina["reports"]));
        Assert.Equal(new[] { "identity.basic" }, Strings(marina["fields"]));
        var decision = Assert.Single(marina["report_decisions"]!.AsArray())!;
        Assert.Equal(new[] { "view" }, Strings(decision["actions"]));
        var trace = Assert.Single(decision["trace"]!.AsArray())!;
        Assert.Equal("group", trace["source_type"]!.GetValue<string>());
        Assert.Equal("ИБ · операторы", trace["source"]!.GetValue<string>());
        Assert.Null(trace["valid_until"]);
        Assert.Empty(marina["direct_reports"]!.AsArray());
    }

    [Fact]
    public void ClientCannotSupplyGrantsAndReturnedJsonCannotMutateDefinitions()
    {
        using var payload = JsonDocument.Parse("""{"actor":"admin","fixture":"sli-universal-prototype-v4","reports":["ad-summary"],"capabilities":["entity.view"],"server_evaluated":false}""");
        var result = SliV4Fixture.Evaluate(payload.RootElement);
        Assert.Equal(new[] { "project-readiness", "technical-events" }, Strings(result["reports"]));
        Assert.True(result["server_evaluated"]!.GetValue<bool>());
        result["packages"]![0]!["key"] = "ad-auditors";
        Assert.Equal("project-ops", Evaluate("admin")["packages"]![0]!["key"]!.GetValue<string>());
    }

    [Theory]
    [InlineData(null, "http://localhost:5000", 404)]
    [InlineData("false", "http://localhost:5000", 404)]
    [InlineData("1", "http://0.0.0.0:5000", 404)]
    [InlineData("1", "http://[::]:5000", 404)]
    [InlineData("1", "http://192.0.2.5:5000", 404)]
    [InlineData("1", "http://example.test:5000", 404)]
    [InlineData("1", "", 404)]
    [InlineData("1", "http://localhost:5000;http://0.0.0.0:5001", 404)]
    [InlineData("1", "http://localhost:5000", 200)]
    [InlineData(" TRUE ", "http://127.0.0.1:5000", 200)]
    [InlineData("yes", "http://[::1]:5000", 200)]
    [InlineData("on", "http://localhost.:5000", 200)]
    public async Task SessionRouteRequiresFlagAndActualLoopbackListeners(string? flag, string bindings, int status)
    {
        using var host = await CreateHost(flag, bindings);
        using var client = host.GetTestClient();
        using var request = Request("""{"actor":"admin","fixture":"sli-universal-prototype-v4"}""");
        request.Headers.Host = "localhost";
        request.Headers.Add("X-Forwarded-Host", "localhost");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(status, (int)response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        if (status == 200)
        {
            Assert.Equal("ok", body["status"]!.GetValue<string>());
            Assert.True(JsonNode.DeepEquals(Evaluate("admin"), body["decision"]));
            Assert.Equal("sli_v4_fixture_actor=admin; Path=/; SameSite=Strict", Assert.Single(response.Headers.GetValues("Set-Cookie")));
        }
        else
        {
            Assert.Equal("not_found", body["error"]!.GetValue<string>());
            Assert.False(response.Headers.Contains("Set-Cookie"));
        }
        await host.StopAsync(TestContext.Current.CancellationToken);
    }

    [Theory]
    [InlineData("""{"actor":"root","fixture":"sli-universal-prototype-v4"}""", "invalid_sli_v4_fixture_actor")]
    [InlineData("[]", "json_object_required")]
    [InlineData("{", "invalid_json")]
    public async Task SessionInputErrorsDoNotIssueCookie(string payload, string error)
    {
        using var host = await CreateHost("1", "http://localhost:5000");
        using var client = host.GetTestClient();
        using var request = Request(payload);
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal(error, body["error"]!.GetValue<string>());
        Assert.False(response.Headers.Contains("Set-Cookie"));
        await host.StopAsync(TestContext.Current.CancellationToken);
    }

    private static HttpRequestMessage Request(string payload) => new(HttpMethod.Post, "/api/test/sli-v4/session")
    { Content = new StringContent(payload, Encoding.UTF8, "application/json") };

    private static async Task<IHost> CreateHost(string? flag, string bindings)
    {
        var host = await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(services =>
        {
            services.AddRouting();
            services.AddSingleton<IConfiguration>(new ConfigurationBuilder().AddInMemoryCollection(
                new Dictionary<string, string?> { ["ADLOG_SLI_V4_FIXTURE"] = flag }).Build());
        }).Configure(app => { app.UseRouting(); app.UseEndpoints(endpoints => endpoints.MapSliV4Fixture()); }))
            .StartAsync(TestContext.Current.CancellationToken);
        var addresses = new ServerAddressesFeature();
        foreach (string binding in bindings.Split(';', StringSplitOptions.RemoveEmptyEntries)) addresses.Addresses.Add(binding);
        host.GetTestServer().Features.Set<IServerAddressesFeature>(addresses);
        return host;
    }
}
