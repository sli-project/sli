using Microsoft.Extensions.Logging;
using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class AgentEndpointTests
{
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
