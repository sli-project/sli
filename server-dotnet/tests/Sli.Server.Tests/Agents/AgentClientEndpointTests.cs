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
public sealed class AgentClientEndpointTests
{
    [Fact]
    public async Task RealRoutesRequireCertificateAndExactPathBeforeAnyDatabaseOrBodyWork()
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
        string address=Assert.Single(host.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses);
        using var client=new HttpClient { BaseAddress=new Uri(address) };
        foreach(var path in new[]{"/api/v1/agent/identity","/api/v1/agent/policy-report"}) {
            using var request=new HttpRequestMessage(path.EndsWith("identity")?HttpMethod.Get:HttpMethod.Post,path);
            request.Headers.Add("X-Client-Cert","synthetic-spoof");request.Headers.Add("X-Forwarded-Proto","https");
            request.Content=path.EndsWith("identity")?null:new StringContent("{}",Encoding.UTF8,"application/json");
            using var response=await client.SendAsync(request,ct);
            Assert.Equal(HttpStatusCode.Unauthorized,response.StatusCode);Assert.Equal("no-store",response.Headers.CacheControl?.ToString());
            var json=JsonNode.Parse(await response.Content.ReadAsByteArrayAsync(ct));Assert.Equal("agent_mtls_required",json!["error"]!.GetValue<string>());
        }
        foreach(var path in new[]{"/API/v1/agent/identity","/api/v1/agent/identity/","/API/v1/agent/policy-report","/api/v1/agent/policy-report/"}) {
            using var request=new HttpRequestMessage(path.Contains("policy-report")?HttpMethod.Post:HttpMethod.Get,path);
            request.Content=new StringContent("not json",Encoding.UTF8,"application/json");using var response=await client.SendAsync(request,ct);
            Assert.Equal(HttpStatusCode.NotImplemented,response.StatusCode);
        }
        using(var duplicate=await client.PostAsync("/api/v1/agent/policy-report",new StringContent("{\"applied_policy_revision\":5,\"applied_policy_revision\":4,\"collection_state\":\"paused\"}",Encoding.UTF8,"application/json"),ct))
            Assert.Equal(HttpStatusCode.Unauthorized,duplicate.StatusCode);
        using(var malformed=await client.PostAsync("/api/v1/agent/policy-report",new StringContent("{",Encoding.UTF8,"application/json"),ct))
            Assert.Equal(HttpStatusCode.BadRequest,malformed.StatusCode);
        using(var oversized=await client.PostAsync("/api/v1/agent/policy-report",new StringContent("{\"untrusted\":\""+new string('x',65536)+"\"}",Encoding.UTF8,"application/json"),ct))
            Assert.Equal(HttpStatusCode.RequestEntityTooLarge,oversized.StatusCode);
    }
}
