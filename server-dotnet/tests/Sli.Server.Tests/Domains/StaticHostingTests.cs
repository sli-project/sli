using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sli.Server.Auth;
using Sli.Server.Hosting;
using Sli.Server.Access;
using Sli.Server.Infrastructure;
using Npgsql;
using Xunit;

namespace Sli.Server.Tests.Domains;

[Collection("Installed API environment")]
public sealed class StaticHostingTests
{
    [Theory]
    [InlineData("/report/vpn.connections?domain=a&x=1")]
    [InlineData("/reports")]
    [InlineData("/settings")]
    [InlineData("/entities/42")]
    [InlineData("/workstations")]
    [InlineData("/workstations?domain_id=11&station=ws%3Aad%3A123")]
    [InlineData("/ad-accounts")]
    [InlineData("/ad-accounts?view=accounts")]
    [InlineData("/agents")]
    [InlineData("/agents?view=policy")]
    [InlineData("/agents/synthetic?view=policy")]
    [InlineData("/notifications")]
    [InlineData("/notifications?nav_view=journal&status=error")]
    [InlineData("/extensions/sli.remote-access/accounts")]
    public async Task BareSpaPathsRedirectThroughHttpRoutingWithQueryPreserved(string raw)
    {
        using var factory = Factory(Path.GetTempPath());
        using var client = factory.CreateClient(new() { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Add("X-Test-Authenticated", "yes");
        using var response = await client.GetAsync(raw, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/app" + raw, response.Headers.Location!.OriginalString);
    }

    [Theory]
    [InlineData("/api/v1/health")]
    [InlineData("/login")]
    [InlineData("/assets/x.js")]
    [InlineData("/nope")]
    [InlineData("/sli-login.css")]
    [InlineData("/reportx")]
    public async Task NonSpaPathsAreNotRedirectedIntoApp(string path)
    {
        using var factory = Factory(Path.GetTempPath());
        using var client = factory.CreateClient(new() { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Add("X-Test-Authenticated", "yes");
        using var response = await client.GetAsync(path, TestContext.Current.CancellationToken);
        Assert.Null(response.Headers.Location);
        Assert.NotEqual(HttpStatusCode.Redirect, response.StatusCode);
    }

    sealed class Round2UnavailableDatabase : IPostgresConnectionFactory
    {
        public int Reads;
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
        { Reads++; throw new InvalidOperationException("sensitive database failure detail; dsn=private-fixture"); }
    }
    sealed class Round2ForbiddenAccess : IAccessFactsRepository
    {
        public Task<AccessFacts> LoadAsync(Principal principal, CancellationToken ct) => throw new InvalidOperationException("access read");
    }
    sealed class Round2ForbiddenAuthentication : IPrincipalAuthenticator
    {
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext context, CancellationToken ct) => throw new InvalidOperationException("authentication read");
    }
    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Round2PublicLivenessAndReadinessAreAccessIndependentAndSanitized(bool authEnabled)
    {
        var database = new Round2UnavailableDatabase();
        using var factory = Factory(Path.GetTempPath(), authOff: !authEnabled).WithWebHostBuilder(builder => builder.ConfigureServices(services =>
        {
            // Count health-request reads, without the independent startup reconciliation.
            foreach (var hosted in services.Where(s => s.ServiceType == typeof(Microsoft.Extensions.Hosting.IHostedService)
                && s.ImplementationType == typeof(Sli.Server.Agents.Registry.AgentRegistrationReconciliation)).ToArray())
                services.Remove(hosted);
            services.RemoveAll<IPostgresConnectionFactory>(); services.AddSingleton<IPostgresConnectionFactory>(database);
            services.RemoveAll<IAccessFactsRepository>(); services.AddSingleton<IAccessFactsRepository, Round2ForbiddenAccess>();
            services.RemoveAll<IPrincipalAuthenticator>(); services.AddSingleton<IPrincipalAuthenticator, Round2ForbiddenAuthentication>();
        }));
        using var client = factory.CreateClient();
        foreach (string path in new[] { "/api/health", "/api/health/live" })
        {
            using var response = await client.GetAsync(path, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var body = System.Text.Json.Nodes.JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
            Assert.Equal("ok", body["status"]!.ToString());
        }
        Assert.Equal(0, database.Reads);
        using var ready = await client.GetAsync("/api/health/ready", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, ready.StatusCode);
        var payload = System.Text.Json.Nodes.JsonNode.Parse(await ready.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.True(System.Text.Json.Nodes.JsonNode.DeepEquals(System.Text.Json.Nodes.JsonNode.Parse("""{"ready":false,"code":"postgres_unavailable"}"""), payload));
        Assert.Equal(1, database.Reads);
    }

    [Fact] public async Task Health_reports_release_metadata_instead_of_frozen_identity()
    {
        using var factory=Factory(Path.GetTempPath()).WithWebHostBuilder(builder=>builder.ConfigureAppConfiguration((_,config)=>config.AddInMemoryCollection(new Dictionary<string,string?> {
            ["Sli:Release:ProjectVersion"]="fixture-version",["Sli:Release:BaselineId"]="fixture-baseline",["Sli:Release:BuildId"]="fixture-build",["Sli:Release:GitCommit"]="0123456789abcdef" })));
        using var client=factory.CreateClient();
        foreach(string path in new[]{"/health","/api/health","/api/health/live"})
        {
            var json=System.Text.Json.Nodes.JsonNode.Parse(await client.GetStringAsync(path,TestContext.Current.CancellationToken))!;
            var identity=json["runtime_identity"]!;
            Assert.Equal("fixture-version",identity["project_version"]!.GetValue<string>());
            Assert.Equal("fixture-baseline",identity["baseline_id"]!.GetValue<string>());
            Assert.Equal("fixture-build",identity["build_id"]!.GetValue<string>());
            Assert.Equal("0123456789abcdef",identity["git_commit"]!.GetValue<string>());
        }
    }
    [Fact]
    public async Task LoginAssetsArePublicAndUnknownApisAreNotSpaPages()
    {
        string root = Path.Combine(Path.GetTempPath(), "sli-hosting-" + Guid.NewGuid());
        Directory.CreateDirectory(Path.Combine(root, "react"));
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root, "login.html"), "<html>existing login</html>", TestContext.Current.CancellationToken);
            await File.WriteAllTextAsync(Path.Combine(root, "sli-login.js"), "existing login script", TestContext.Current.CancellationToken);
            await File.WriteAllTextAsync(Path.Combine(root, "react", "index.html"), "<html>existing app</html>", TestContext.Current.CancellationToken);
            using var factory = Factory(root);
            using var client = factory.CreateClient(new() { AllowAutoRedirect = false });
            Assert.Contains("existing login", await client.GetStringAsync("/login", TestContext.Current.CancellationToken));
            Assert.Equal("existing login script", await client.GetStringAsync("/sli-login.js", TestContext.Current.CancellationToken));
            using var unknown = await client.GetAsync("/api/v99/unknown", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
            using var anonymousPost = await client.PostAsync("/api/v99/missing.json", null, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.Unauthorized, anonymousPost.StatusCode);
            using var anonymousPage = await client.GetAsync("/unknown-page", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.Redirect, anonymousPage.StatusCode);
            Assert.StartsWith("/login?next=", anonymousPage.Headers.Location!.OriginalString);
            client.DefaultRequestHeaders.Add("X-Test-Authenticated", "yes");
            using var authenticated = await client.GetAsync("/api/v99/unknown", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.NotImplemented, authenticated.StatusCode);
            Assert.Contains("\"not_ported\"", await authenticated.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
            using var post = await client.PostAsync("/api/v99/missing.json", null, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.NotImplemented, post.StatusCode);
            using var health = await client.GetAsync("/api/health", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, health.StatusCode);
            Assert.Contains("ad-log-reports", await health.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
            using var ready = await client.GetAsync("/api/health/ready", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, ready.StatusCode);
            Assert.Contains("postgres_unavailable", await ready.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        }
        finally { Directory.Delete(root, true); }
    }

    [Fact]
    public async Task AuthFailureUsesSharedSafeJsonError()
    {
        string root = Path.Combine(Path.GetTempPath(), "sli-hosting-" + Guid.NewGuid());
        Directory.CreateDirectory(root);
        try
        {
            using var factory = Factory(root);
            using var client = factory.CreateClient(new() { AllowAutoRedirect = false });
            client.DefaultRequestHeaders.Add("X-Test-Throw", "yes");
            using var response = await client.GetAsync("/app/", TestContext.Current.CancellationToken);
            string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
            Assert.Contains("internal_error_id", body);
            Assert.DoesNotContain("private-test-value", body);
        }
        finally { Directory.Delete(root, true); }
    }

    [Theory]
    [InlineData("sli-login.css", "a{}", "text/css")]
    [InlineData("assets/sli-login/sli-logo.svg", "<svg/>", "image/svg+xml")]
    public async Task LoginStaticAssetsAreRevalidatedWithoutAuthentication(string path, string content, string contentType)
    {
        string root = Path.Combine(Path.GetTempPath(), "sli-hosting-" + Guid.NewGuid());
        string file = Path.Combine(root, path);
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        try
        {
            await File.WriteAllTextAsync(file, content, TestContext.Current.CancellationToken);
            using var factory = Factory(root);
            using var client = factory.CreateClient(new() { AllowAutoRedirect = false });
            client.DefaultRequestHeaders.Add("X-Test-Throw", "yes");
            using var response = await client.GetAsync("/" + path, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("no-cache", Assert.Single(response.Headers.GetValues("Cache-Control")));
            Assert.Equal(contentType, response.Content.Headers.ContentType!.MediaType);
            Assert.Equal(content, await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        }
        finally { Directory.Delete(root, true); }
    }

    [Fact]
    public async Task ReactShellRequiresAuthenticationAndMissingAssetsDoNotReturnShell()
    {
        string root = Path.Combine(Path.GetTempPath(), "sli-hosting-" + Guid.NewGuid());
        Directory.CreateDirectory(Path.Combine(root, "react"));
        Directory.CreateDirectory(Path.Combine(root, "react", "assets"));
        Directory.CreateDirectory(Path.Combine(root, "react", "reports"));
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root, "react", "index.html"), "<html>existing app</html>", TestContext.Current.CancellationToken);
            await File.WriteAllTextAsync(Path.Combine(root, "react", "assets", "main.js"), "test asset", TestContext.Current.CancellationToken);
            using var factory = Factory(root);
            using var client = factory.CreateClient(new() { AllowAutoRedirect = false });
            using var anonymous = await client.GetAsync("/app/", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.Redirect, anonymous.StatusCode);
            Assert.StartsWith("/login?next=", anonymous.Headers.Location!.OriginalString);
            Assert.Equal("no-store, max-age=0", anonymous.Headers.CacheControl!.ToString());
            Assert.Equal("DENY", Assert.Single(anonymous.Headers.GetValues("X-Frame-Options")));
            client.DefaultRequestHeaders.Add("X-Test-Authenticated", "yes");
            using var redirect = await client.GetAsync("https://localhost/", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, redirect.StatusCode);
            Assert.Equal("max-age=15552000; includeSubDomains", Assert.Single(redirect.Headers.GetValues("Strict-Transport-Security")));
            Assert.Equal("no-cache", redirect.Headers.CacheControl!.ToString());
            Assert.Contains("frame-ancestors 'none'", Assert.Single(redirect.Headers.GetValues("Content-Security-Policy")));
            // test_static_cache_headers.py: shell and dotted client-route fallback revalidate.
            foreach (string path in new[] { "/", "/app", "/app/", "/app/index.html", "/app/reports/ad.gpo.review" })
            {
                using var shell = await client.GetAsync(path, TestContext.Current.CancellationToken);
                Assert.Equal(HttpStatusCode.OK, shell.StatusCode);
                Assert.Equal("no-cache", Assert.Single(shell.Headers.GetValues("Cache-Control")));
                Assert.Equal("text/html", shell.Content.Headers.ContentType!.MediaType);
                Assert.Contains("existing app", await shell.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
            }
            using var deep = await client.GetAsync("/app/some/deep", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, deep.StatusCode);
            Assert.Equal("no-cache", deep.Headers.CacheControl!.ToString());
            using var builtAsset = await client.GetAsync("/app/assets/main.js", TestContext.Current.CancellationToken);
            Assert.Equal("application/javascript; charset=utf-8", builtAsset.Content.Headers.ContentType!.ToString());
            Assert.Equal("public, max-age=31536000, immutable", builtAsset.Headers.CacheControl!.ToString());
            Assert.Equal("test asset", await builtAsset.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
            using var legacy = await client.GetAsync("/events/123?q=1", TestContext.Current.CancellationToken);
            Assert.Equal("/app/events/123?q=1", legacy.Headers.Location!.OriginalString);
            using var escaped = await client.GetAsync("/events/a%23b%3Fc?q=1", TestContext.Current.CancellationToken);
            Assert.Equal("/app/events/a%23b%3Fc?q=1", escaped.Headers.Location!.OriginalString);
            using var directory = await client.GetAsync("/app/reports/", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, directory.StatusCode);
            Assert.Contains("existing app", await directory.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
            using var assetDirectory = await client.GetAsync("/app/assets/", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, assetDirectory.StatusCode);
            using var asset = await client.GetAsync("/app/assets/missing.js", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, asset.StatusCode);
            Assert.Equal("no-store, max-age=0", Assert.Single(asset.Headers.GetValues("Cache-Control")));
            Assert.Equal("application/json", asset.Content.Headers.ContentType!.MediaType);
            using var error = System.Text.Json.JsonDocument.Parse(await asset.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
            Assert.True(error.RootElement.TryGetProperty("error", out _));
            Assert.Equal("react_ui_not_built", System.Text.Json.Nodes.JsonNode.Parse(await asset.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!["error"]!.ToString());
        }
        finally { Directory.Delete(root, true); }
    }

    [Fact]
    public async Task BundledAgentRequiresLoginAndDownloadsThePackage()
    {
        string root = Path.Combine(Path.GetTempPath(), "sli-hosting-" + Guid.NewGuid());
        Directory.CreateDirectory(Path.Combine(root, "installers"));
        var ct = TestContext.Current.CancellationToken;
        const string url = "https://localhost/app/installers/SliAgent.msi";
        byte[] payload = [0, 1, 2, 255];
        try
        {
            await File.WriteAllBytesAsync(Path.Combine(root, "installers", "SliAgent.msi"), payload, ct);
            using var factory = Factory(root);
            using var client = factory.CreateClient(new() { AllowAutoRedirect = false });
            using var anonymous = await client.GetAsync(url, ct);
            Assert.Equal(HttpStatusCode.Redirect, anonymous.StatusCode);
            Assert.StartsWith("/login?next=", anonymous.Headers.Location!.OriginalString);

            client.DefaultRequestHeaders.Add("X-Test-Authenticated", "yes");
            using var response = await client.GetAsync(url, ct);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("SliAgent.msi", response.Content.Headers.ContentDisposition!.FileName);
            Assert.True(response.Headers.CacheControl!.NoStore);
            Assert.Equal(payload, await response.Content.ReadAsByteArrayAsync(ct));
            using var missing = await client.GetAsync("https://localhost/app/installers/SliAgent-publish-win-x64.zip", ct);
            Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
        }
        finally { Directory.Delete(root, true); }
    }

    [Fact]
    public async Task ExplicitAuthOptOutServesReactWithoutCallingAuthenticator()
    {
        string root = Path.Combine(Path.GetTempPath(), "sli-hosting-" + Guid.NewGuid());
        Directory.CreateDirectory(Path.Combine(root, "react"));
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root, "react", "index.html"), "<html>existing app</html>", TestContext.Current.CancellationToken);
            using var factory = Factory(root, authOff: true);
            using var client = factory.CreateClient(new() { AllowAutoRedirect = false });
            client.DefaultRequestHeaders.Add("X-Test-Throw", "yes");
            using var response = await client.GetAsync("/app/", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Contains("existing app", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        }
        finally { Directory.Delete(root, true); }
    }

    [Theory]
    [InlineData("../react-backup/secret.txt")]
    [InlineData("assets/../../react-backup/secret.txt")]
    public async Task ReactRejectsPathsOutsideRootInsteadOfServingSiblingOrShell(string path)
    {
        string root = Path.Combine(Path.GetTempPath(), "sli-hosting-" + Guid.NewGuid());
        Directory.CreateDirectory(Path.Combine(root, "react"));
        Directory.CreateDirectory(Path.Combine(root, "react-backup"));
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root, "react", "index.html"), "app", TestContext.Current.CancellationToken);
            await File.WriteAllTextAsync(Path.Combine(root, "react-backup", "secret.txt"), "outside-root-fixture", TestContext.Current.CancellationToken);
            using var factory = Factory(root);
            using var client = factory.CreateClient();
            var context = await factory.Server.SendAsync(c => {
                c.Request.Method = "GET";
                c.Request.Path = "/app/" + path;
                c.Request.Headers["X-Test-Authenticated"] = "yes";
            }, TestContext.Current.CancellationToken);
            using var reader = new StreamReader(context.Response.Body);
            Assert.Equal(404, context.Response.StatusCode);
            Assert.Equal("not_found", System.Text.Json.Nodes.JsonNode.Parse(await reader.ReadToEndAsync(TestContext.Current.CancellationToken))!["error"]!.ToString());
        }
        finally { Directory.Delete(root, true); }
    }

    [Theory]
    [InlineData("reports/ad.gpo.review")]
    [InlineData("reports/security.queue")]
    public async Task ReactDottedRoutesServeHtmlShell(string path)
    {
        string root = Path.Combine(Path.GetTempPath(), "sli-hosting-" + Guid.NewGuid());
        Directory.CreateDirectory(Path.Combine(root, "react"));
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root, "react", "index.html"), "app", TestContext.Current.CancellationToken);
            using var factory = Factory(root);
            using var client = factory.CreateClient();
            client.DefaultRequestHeaders.Add("X-Test-Authenticated", "yes");
            using var response = await client.GetAsync("/app/" + path, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("app", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
            Assert.Equal("text/html; charset=utf-8", response.Content.Headers.ContentType!.ToString());
        }
        finally { Directory.Delete(root, true); }
    }

    [Fact]
    public async Task ReactEnvironmentOverrideServesIsolatedJavascriptBuild()
    {
        string root = Path.Combine(Path.GetTempPath(), "sli-hosting-" + Guid.NewGuid());
        string isolated = Path.Combine(root, "http-check-build");
        Directory.CreateDirectory(Path.Combine(isolated, "assets"));
        string? previous = Environment.GetEnvironmentVariable("ADLOG_REACT_WEB_DIR");
        try
        {
            await File.WriteAllTextAsync(Path.Combine(isolated, "assets", "app.js"), "console.log('isolated')", TestContext.Current.CancellationToken);
            Environment.SetEnvironmentVariable("ADLOG_REACT_WEB_DIR", isolated);
            using var factory = Factory(Path.Combine(root, "unused-web-root"));
            using var client = factory.CreateClient();
            client.DefaultRequestHeaders.Add("X-Test-Authenticated", "yes");
            using var response = await client.GetAsync("/app/assets/app.js", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("console.log('isolated')", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
            Assert.Equal("application/javascript; charset=utf-8", response.Content.Headers.ContentType!.ToString());
        }
        finally { Environment.SetEnvironmentVariable("ADLOG_REACT_WEB_DIR", previous); Directory.Delete(root, true); }
    }

    private static WebApplicationFactory<Program> Factory(string root, bool authOff = false) => new WebApplicationFactory<Program>().WithWebHostBuilder(Sli.Server.Tests.Domains.SafeTestEnvironment.ConfigureApiHost).WithWebHostBuilder(builder =>
    {
        builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?> {
            ["Sli:WebRoot"] = root, ["Sli:AuthRequired"] = authOff ? "0" : "1", ["Sli:AllowUnauthenticated"] = authOff ? "1" : "0" }));
        builder.ConfigureServices(services =>
        {
            services.RemoveAll<IPrincipalAuthenticator>();
            services.AddSingleton<IPrincipalAuthenticator, TestAuthenticator>();
        });
    });

    private sealed class TestAuthenticator : IPrincipalAuthenticator
    {
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext context, CancellationToken ct) =>
            context.Request.Headers.ContainsKey("X-Test-Throw") ? throw new InvalidOperationException("private-test-value") :
            ValueTask.FromResult(context.Request.Headers.ContainsKey("X-Test-Authenticated")
                ? AuthenticationResult.Success(new Principal("session", 1, "viewer"))
                : AuthenticationResult.Denied(401, "authentication_required"));
    }
}
