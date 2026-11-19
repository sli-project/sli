using Microsoft.Extensions.Logging;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sli.Server.Agents.Control;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class AgentEndpointTests
{
    [Fact]
    public async Task Installer_download_is_anonymous_over_https_and_reports_missing_package()
    {
        var ct = TestContext.Current.CancellationToken;
        string path = Path.Combine(Path.GetTempPath(), $"sli-test-{Guid.NewGuid():N}.msi");
        byte[] package = "synthetic MSI"u8.ToArray();
        try
        {
            await File.WriteAllBytesAsync(path, package, ct);
            using var host = new WebApplicationFactory<Program>().WithWebHostBuilder(builder => builder
                .ConfigureLogging(logging => logging.ClearProviders())
                .ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Sli:AgentInstallerPath"] = path, ["Sli:AgentMtlsCaFile"] = "", ["Sli:AuthRequired"] = "1",
                    ["Sli:AuthAllowInsecureHttp"] = "1", ["Sli:OwnerSetup"] = "0"
                })));
            using var httpClient = host.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
            using var http = await httpClient.GetAsync(AgentConsolePackage.DownloadPath, ct);
            Assert.Equal(HttpStatusCode.NotFound, http.StatusCode);

            using var client = host.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://sli.example.test") });
            using var https = await client.GetAsync(AgentConsolePackage.DownloadPath, ct);
            Assert.Equal(HttpStatusCode.OK, https.StatusCode);
            Assert.Equal("no-store", https.Headers.CacheControl?.ToString());
            Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(package)), Assert.Single(https.Headers.GetValues("X-SLI-Package-SHA256")));
            Assert.Equal("SliAgent.msi", https.Content.Headers.ContentDisposition?.FileName);
            Assert.Equal(package, await https.Content.ReadAsByteArrayAsync(ct));

            File.Delete(path);
            using var missing = await client.GetAsync(AgentConsolePackage.DownloadPath, ct);
            Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
            using var error = JsonDocument.Parse(await missing.Content.ReadAsByteArrayAsync(ct));
            Assert.Equal("agent_console_package_unavailable", error.RootElement.GetProperty("error").GetString());
        }
        finally { File.Delete(path); }
    }

    [Theory]
    [InlineData("a'b", "'a''b'")]
    [InlineData("a\u2018\u2019\u201a\u201b\u201cb\u201d", "'a\u2018\u2018\u2019\u2019\u201a\u201a\u201b\u201b\u201cb\u201d'")]
    public void Installer_arguments_escape_PowerShell_single_quotes(string value, string literal) =>
        Assert.Equal(literal, AgentConsolePackage.QuotePowerShell(value));

    [Fact]
    public async Task PlainHttpCannotEnrollRenewOrSubmitPacket()
    {
        var ct = TestContext.Current.CancellationToken;
        using var host = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
            builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sli:AgentMtlsCaFile"] = "", ["urls"] = "http://127.0.0.1:0", ["Sli:TrustedProxies"] = "", ["Sli:AuthRequired"] = "1",
                ["Sli:AuthAllowInsecureHttp"] = "1", ["Sli:OwnerSetup"] = "0"
            }))).WithWebHostBuilder(b => b.ConfigureLogging(logging => logging.ClearProviders()).ConfigureServices(services => {
            foreach (var worker in services.Where(d => d.ServiceType == typeof(Microsoft.Extensions.Hosting.IHostedService)
                && (d.ImplementationType == typeof(Sli.Server.Workspace.DashboardWarmupService)
                    || d.ImplementationType == typeof(Sli.Server.Legacy.LegacyJobWorker)
                    || d.ImplementationType == typeof(Sli.Server.Legacy.LegacyScheduler)
                    || d.ImplementationType == typeof(Sli.Server.Legacy.LegacyPostCollectionHostedService))).ToArray())
                services.Remove(worker);
        }));
        host.UseKestrel(options => options.Listen(IPAddress.Loopback, 0));
        host.StartServer();
        string address = Assert.Single(host.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses);
        Assert.True(new Uri(address).IsLoopback);
        using var client = new HttpClient { BaseAddress = new Uri(address) };
        foreach (var (route, code) in new[]
        {
            ("/api/v1/agent/enroll", "agent_tls_required"),
            ("/api/v1/agent/renew", "agent_mtls_required"),
            ("/api/v1/agent/packets", "agent_authentication_failed")
        })
        {
            using var content = new StringContent("{}", Encoding.UTF8, "application/json");
            using var response = await client.PostAsync(route, content, ct);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
            using var body = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(ct));
            Assert.Equal(code, body.RootElement.GetProperty("error").GetString());
        }
        foreach (string route in new[] { "/API/v1/agent/enroll", "/api/v1/agent/enroll/",
            "/api/v1/agent/Renew", "/api/v1/agent/renew/", "/api/v1/agent/Packets", "/api/v1/agent/packets/" })
        {
            using var content = new StringContent("not json", Encoding.UTF8, "text/plain");
            using var response = await client.PostAsync(route, content, ct);
            Assert.Equal(HttpStatusCode.NotImplemented, response.StatusCode);
            using var body = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(ct));
            Assert.Equal("not_implemented", body.RootElement.GetProperty("error").GetString());
        }
    }
}
