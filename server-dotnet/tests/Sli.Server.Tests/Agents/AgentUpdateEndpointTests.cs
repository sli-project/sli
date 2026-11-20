using Microsoft.Extensions.Logging;
using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
namespace Sli.Server.Tests.Agents;
public sealed class AgentUpdateEndpointTests
{
    [Fact]
    public async Task ConcreteUpdateRoutesPreserveCertificateBodyAndExactPathPrecedence()
    {
        var ct=TestContext.Current.CancellationToken;
        using var host=new WebApplicationFactory<Program>().WithWebHostBuilder(b=>b.ConfigureAppConfiguration((_,cfg)=>cfg.AddInMemoryCollection(new Dictionary<string,string?> {
            ["Sli:AgentMtlsCaFile"]="",["urls"] = "http://127.0.0.1:0", ["Sli:TrustedProxies"]="",["Sli:AuthRequired"]="1",["Sli:AuthAllowInsecureHttp"]="1",["Sli:OwnerSetup"]="0" }))).WithWebHostBuilder(b => b.ConfigureLogging(logging => logging.ClearProviders()).ConfigureServices(services => {
            foreach (var worker in services.Where(d => d.ServiceType == typeof(Microsoft.Extensions.Hosting.IHostedService)
                && (d.ImplementationType == typeof(Sli.Server.Workspace.DashboardWarmupService)
                    || d.ImplementationType == typeof(Sli.Server.Legacy.LegacyJobWorker)
                    || d.ImplementationType == typeof(Sli.Server.Legacy.LegacyScheduler)
                    || d.ImplementationType == typeof(Sli.Server.Legacy.LegacyPostCollectionHostedService))).ToArray())
                services.Remove(worker);
        }));
        host.UseKestrel(k=>k.Listen(IPAddress.Loopback,0));host.StartServer();
        using var client=new HttpClient { BaseAddress=new Uri(Assert.Single(host.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses)) };
        foreach(string path in new[]{"/api/v1/agent/package?sha256=wrong","/api/v1/agent/update-result"}) {
            using var request=new HttpRequestMessage(path.Contains("package")?HttpMethod.Get:HttpMethod.Post,path);
            request.Headers.Add("X-Client-Cert","synthetic-spoof");request.Headers.Add("X-Forwarded-Proto","https");
            request.Headers.Add("Range","bytes=0-1");request.Content=path.Contains("package")?null:new StringContent("{}",Encoding.UTF8,"application/json");
            using var response=await client.SendAsync(request,ct);Assert.Equal(HttpStatusCode.Unauthorized,response.StatusCode);
            Assert.Equal("no-store",response.Headers.CacheControl?.ToString());Assert.Equal("agent_mtls_required",JsonNode.Parse(await response.Content.ReadAsByteArrayAsync(ct))!["error"]!.GetValue<string>());
        }
        foreach(string path in new[]{"/API/v1/agent/package","/api/v1/agent/package/","/API/v1/agent/update-result","/api/v1/agent/update-result/"}) {
            using var request=new HttpRequestMessage(path.Contains("package")?HttpMethod.Get:HttpMethod.Post,path);request.Content=new StringContent("{",Encoding.UTF8,"application/json");
            using var response=await client.SendAsync(request,ct);Assert.Equal(HttpStatusCode.NotImplemented,response.StatusCode);
        }
        using var malformed=await client.PostAsync("/api/v1/agent/update-result",new StringContent("{",Encoding.UTF8,"application/json"),ct);
        Assert.Equal(HttpStatusCode.BadRequest,malformed.StatusCode);
        using var duplicate=await client.PostAsync("/api/v1/agent/update-result",new StringContent("{\"status\":1,\"status\":\"updated\"}",Encoding.UTF8,"application/json"),ct);
        Assert.Equal(HttpStatusCode.Unauthorized,duplicate.StatusCode);
    }
}
