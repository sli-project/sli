using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
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
using Sli.Server.Operations;
using Xunit;

namespace Sli.Server.Tests.Compatibility;

public sealed class DbStatusReportTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static JsonObject Reference()
    {
        using var stream = typeof(DbStatusReportTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Compatibility.db-status-reference.json")!;
        return JsonNode.Parse(stream)!.AsObject();
    }
    static JsonObject Fixture(string name) => Reference()["cases"]!.AsArray().OfType<JsonObject>().Single(c => (string?)c["name"] == name);
    public static TheoryData<string> Cases => new(Reference()["cases"]!.AsArray().Select(c => (string)c!["name"]!).ToArray());
    sealed class OperationalError(string message) : Exception(message);
    sealed class Queries(JsonObject fixture) : IOperationsQueries
    {
        public List<string> Calls = [];
        public Task<JsonArray> ReadAsync(string sql, CancellationToken ct, params (string Name, object? Value)[] parameters)
            => throw new InvalidOperationException("Report must use the readiness reader without statement limits");
        public Task<JsonArray> ReadReadinessAsync(string sql, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            Calls.Add(sql);
            string stage = sql.Contains("information_schema") ? "tables" : sql.Contains("from schema_migrations") ? "migrations" : "identity";
            if ((string?)fixture["error_stage"] == stage)
            {
                if ((string?)fixture["error_sqlstate"] is {} state) throw new Npgsql.PostgresException("fixture <connection> & 'unavailable'", "ERROR", "ERROR", state);
                throw new OperationalError("fixture <connection> & 'unavailable'");
            }
            return Task.FromResult(stage switch {
                "tables" => new JsonArray(fixture["tables"]!.AsArray().Select(t => (JsonNode)new JsonObject { ["table_name"] = t!.DeepClone() }).ToArray()),
                "migrations" => fixture["migrations"]!.DeepClone().AsArray(),
                _ => new JsonArray(new JsonObject { ["version"] = "PostgreSQL fixture <version>", ["database"] = "fixture", ["user"] = "fixture_reader" })
            });
        }
    }
    sealed class Auth(string? role) : IPrincipalAuthenticator
    {
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext context, CancellationToken ct) => ValueTask.FromResult(role is null
            ? AuthenticationResult.Denied(401, "authentication_required") : AuthenticationResult.Success(new("session", 1, role)));
    }
    sealed class Facts(bool allowed) : IAccessFactsRepository
    {
        public int Reads;
        public Task<AccessFacts> LoadAsync(Principal p, CancellationToken ct)
        {
            Reads++;
            return Task.FromResult(new AccessFacts(false, p.Role, [], [], allowed ? [JsonSerializer.SerializeToElement(new { capability_key = "operations.view", effect = "allow", scope_json = new { kind = "all" } })] : [], [], [], [], []));
        }
    }
    sealed class App(IHost host, string directory, Queries queries, Facts facts) : IDisposable
    {
        public HttpClient Client { get; } = host.GetTestClient();
        public Queries Queries => queries;
        public Facts Facts => facts;
        public void Dispose() { Client.Dispose(); host.Dispose(); File.Delete(Path.Combine(directory, "fixture.db")); Directory.Delete(directory); }
    }
    static async Task<App> Start(JsonObject fixture, string? role = "operator", bool allowed = true, bool required = true, string? timeout = null)
    {
        string directory = Path.Combine(Path.GetTempPath(), "sli-db-status-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "fixture.db");
        if (fixture["size"] is {} size) File.WriteAllBytes(path, new byte[size.GetValue<int>()]);
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            ["Sli:AuthRequired"] = required ? "true" : "false", ["Sli:AllowUnauthenticated"] = required ? "false" : "true",
            ["Sli:ProjectRoot"] = directory, ["Sli:DataDirectory"] = directory,
            ["Sli:Operations:ADLOG_DB_PATH"] = path, ["Sli:Operations:ADLOG_PG_DSN"] = (string?)fixture["dsn"] ?? "",
            ["Sli:Operations:ADLOG_PG_CONNECT_TIMEOUT_SECONDS"] = timeout ?? "3"
        }).Build();
        var queries = new Queries(fixture); var facts = new Facts(allowed);
        var host = await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(s => {
            s.AddRouting(); s.AddLogging(); s.AddSingleton<IConfiguration>(config);
            s.AddSingleton(new AuthRequestPolicy(config)); s.AddSingleton(new TransportGate(config));
            s.AddSingleton<IPrincipalAuthenticator>(new Auth(role)); s.AddSingleton<IAccessFactsRepository>(facts);
            s.AddSingleton<IOperationsQueries>(queries); s.AddLegacyHttp();
        }).Configure(app => { app.UseRouting(); app.UseReadRoleRequestGate(); app.UseEndpoints(e => e.MapLegacyHttp()); })).StartAsync(Ct);
        return new(host, directory, queries, facts);
    }
    [Theory, MemberData(nameof(Cases))]
    public async Task HtmlAndStatusesMatchPythonDiagnosticsFixtures(string name)
    {
        var fixture = Fixture(name);
        using var app = await Start(fixture);
        using var response = await app.Client.GetAsync("/reports/db-status.html?connect=false&connect=&limit=bad&force=bad&q=%3Cscript%3E", Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Equal("text/html; charset=utf-8", response.Content.Headers.ContentType!.ToString());
        string html = await response.Content.ReadAsStringAsync(Ct);
        Assert.Equal(System.Text.Encoding.UTF8.GetByteCount(html), response.Content.Headers.ContentLength);
        var nonce = Regex.Match(html, "<style nonce=\"([A-Za-z0-9_-]{32})\">");
        Assert.True(nonce.Success);
        string csp = Assert.Single(response.Headers.GetValues("Content-Security-Policy"));
        Assert.Contains("'nonce-" + nonce.Groups[1].Value + "'", csp);
        html = html.Replace(nonce.Value, "<style>");
        html = Regex.Replace(html, @"<p>Duration: \d+ ms</p>", "<p>Duration: 0 ms</p>");
        // Only the local legacy file path and monotonic duration differ between runtimes.
        html = Regex.Replace(html, "<p>Path: <code>.*?</code></p>", "<p>Path: <code>fixture/ad_logs.sqlite</code></p>");
        Assert.Equal((string?)fixture["html"], html);
        Assert.DoesNotContain("fixture-password", html);
        Assert.DoesNotContain("<script>", html);
        Assert.All(app.Queries.Calls, sql => Assert.StartsWith("select ", sql));
        if (name == "no_dsn") Assert.Empty(app.Queries.Calls);
        else if (name is "failed_identity" or "connection_uri_failure") Assert.Single(app.Queries.Calls);
        else Assert.InRange(app.Queries.Calls.Count, 2, 3);
    }
    [Fact]
    public void EmptyNullAndUntrustedNestedValuesMatchPythonEscapingExactly()
    {
        foreach (var fixture in Reference()["renders"]!.AsArray())
            Assert.Equal((string?)fixture!["html"], DbStatusReport.Render(fixture["data"]!.AsObject()));
    }
    [Fact]
    public void DsnRedactionMatchesPythonAndFailsClosed()
    {
        foreach (var fixture in Reference()["dsns"]!.AsArray())
            Assert.Equal((string?)fixture!["expected"], DbStatusReport.RedactDsn((string)fixture["input"]!));
        Assert.DoesNotContain("fixture-password", DbStatusReport.RedactDsn("Host=192.0.2.10;Database=fixture;Username=fixture;Password=fixture-password", native: true));
    }
    [Theory]
    [InlineData(null, true, 302, 0)]
    [InlineData("viewer", true, 302, 0)]
    [InlineData("technical", true, 302, 0)]
    [InlineData("operator", false, 403, 1)]
    [InlineData("admin", true, 200, 1)]
    [InlineData("operator", true, 200, 1)]
    public async Task AuthorizationPrecedesReadsAndIgnoredQuery(string? role, bool allowed, int status, int accessReads)
    {
        using var app = await Start(Fixture("complete"), role, allowed);
        using var response = await app.Client.GetAsync("/reports/db-status.html?limit=bad&connect=false", Ct);
        Assert.Equal(status, (int)response.StatusCode); Assert.Equal(accessReads, app.Facts.Reads);
        if (status != 200) Assert.Empty(app.Queries.Calls);
        if (role is null) Assert.Equal("/login?next=%2Freports%2Fdb-status.html%3Flimit%3Dbad%26connect%3Dfalse", response.Headers.Location!.ToString());
        else if (status == 302) Assert.Equal("/", response.Headers.Location!.ToString());
        if (status == 403) Assert.Equal("operations.view", (string?)JsonNode.Parse(await response.Content.ReadAsStringAsync(Ct))!["required_capability"]);
    }
    [Fact]
    public async Task AuthDisabledStillUsesCapabilityGate()
    {
        using (var app = await Start(Fixture("no_dsn"), role: null, required: false))
        using (var response = await app.Client.GetAsync("/reports/db-status.html", Ct)) Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using (var app = await Start(Fixture("complete"), role: null, required: false, allowed: false))
        using (var response = await app.Client.GetAsync("/reports/db-status.html", Ct)) { Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); Assert.Empty(app.Queries.Calls); }
    }
    [Theory]
    [InlineData("/REPORTS/DB-STATUS.HTML")]
    [InlineData("/reports/db-status.html/")]
    [InlineData("/REPORTS/DB-STATUS.HTML/")]
    public async Task FrameworkRouteAliasesKeepTheCapabilityGate(string path)
    {
        using (var app = await Start(Fixture("no_dsn")))
        using (var response = await app.Client.GetAsync(path, Ct)) Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using (var app = await Start(Fixture("complete"), allowed: false))
        using (var response = await app.Client.GetAsync(path, Ct)) { Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); Assert.Empty(app.Queries.Calls); }
    }
    [Fact]
    public async Task InvalidServerSettingReturnsCorrelatedErrorWithoutDatabaseRead()
    {
        using var app = await Start(Fixture("complete"), timeout: "invalid-fixture-setting");
        using var response = await app.Client.GetAsync("/reports/db-status.html", Ct);
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode); Assert.Empty(app.Queries.Calls);
        string body = await response.Content.ReadAsStringAsync(Ct);
        Assert.Contains("internal_server_error", body); Assert.Contains("internal_error_id", body);
        Assert.DoesNotContain("invalid-fixture-setting", body); Assert.DoesNotContain("fixture-password", body);
    }
    [Fact]
    public async Task YamlDatabaseSettingsAndNativeConfigurationAreReportedWithoutPasswords()
    {
        string directory = Path.Combine(Path.GetTempPath(), "sli-db-status-config-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(directory, "config"));
        string yaml = Path.Combine(directory, "config", "adlog_config.yaml");
        try
        {
            File.WriteAllText(yaml, "database:\n  postgres_dsn: host=192.0.2.10 user=fixture password=fixture-password dbname=fixture\n  postgres_connect_timeout_seconds: 9\n");
            var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
                ["Sli:ProjectRoot"] = directory, ["Sli:DataDirectory"] = directory,
                ["Sli:Operations:ADLOG_PG_DSN"] = "", ["Sli:Operations:ADLOG_PG_CONNECT_TIMEOUT_SECONDS"] = "", ["Sli:Operations:ADLOG_DB_PATH"] = " "
            }).Build();
            var queries = new Queries(Fixture("complete"));
            var service = new DbStatusReport(queries, new OperationsFiles(config), config);
            var data = await service.ReadAsync(Ct);
            Assert.Equal(Path.Combine(directory, "processed", "ad_logs.sqlite"), (string?)data["sqlite"]!["path"]);
            Assert.True((bool)data["postgres"]!["configured"]!); Assert.Equal(9, (int)data["postgres"]!["connect_timeout_seconds"]!);
            config["Sli:Operations:ADLOG_PG_CONNECT_TIMEOUT_SECONDS"] = "11";
            data = await service.ReadAsync(Ct);
            Assert.Equal(11, (int)data["postgres"]!["connect_timeout_seconds"]!);
            Assert.DoesNotContain("fixture-password", data.ToJsonString());
            File.Delete(yaml);
            config["ConnectionStrings:Sli"] = "Host=192.0.2.10;Database=fixture;Username=fixture;Password=fixture-password";
            data = await service.ReadAsync(Ct);
            Assert.True((bool)data["postgres"]!["configured"]!); Assert.DoesNotContain("fixture-password", data.ToJsonString());
            using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => service.ReadAsync(cancelled.Token));
        }
        finally { File.Delete(yaml); Directory.Delete(Path.Combine(directory, "config")); Directory.Delete(directory); }
    }
}
