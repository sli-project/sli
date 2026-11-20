using Npgsql;
using Sli.Server.Infrastructure;
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
public sealed class AgentDiagnosticsEndpointTests
{
    private sealed class NoDatabase:IPostgresConnectionFactory
    {
        public int Opens;
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct){Interlocked.Increment(ref Opens);throw new Xunit.Sdk.XunitException("Database opens are forbidden in API guards");}
    }
    [Fact]
    public async Task FiveRealRoutesKeepIndependentAuthorityBodyPrecedenceAndExactPaths()
    {
        var ct=TestContext.Current.CancellationToken;var database=new NoDatabase();
        using var host=new WebApplicationFactory<Program>().WithWebHostBuilder(b=>b.ConfigureServices(s=>s.AddSingleton<IPostgresConnectionFactory>(database)).ConfigureLogging(l=>l.ClearProviders()).ConfigureAppConfiguration((_,cfg)=>cfg.AddInMemoryCollection(new Dictionary<string,string?> {
            ["Sli:AgentMtlsCaFile"]="",["urls"] = "http://127.0.0.1:0", ["Sli:TrustedProxies"]="",["Sli:AuthRequired"]="0",["Sli:AllowUnauthenticated"]="1",["Sli:AuthAllowInsecureHttp"]="1",["Sli:OwnerSetup"]="0" }))).WithWebHostBuilder(b => b.ConfigureLogging(logging => logging.ClearProviders()).ConfigureServices(services => {
            foreach (var worker in services.Where(d => d.ServiceType == typeof(Microsoft.Extensions.Hosting.IHostedService)
                && (d.ImplementationType == typeof(Sli.Server.Workspace.DashboardWarmupService)
                    || d.ImplementationType == typeof(Sli.Server.Agents.Registry.AgentRegistrationReconciliation)
                    || d.ImplementationType == typeof(Sli.Server.Legacy.LegacyJobWorker)
                    || d.ImplementationType == typeof(Sli.Server.Legacy.LegacyScheduler)
                    || d.ImplementationType == typeof(Sli.Server.Legacy.LegacyPostCollectionHostedService))).ToArray())
                services.Remove(worker);
        }));
        host.UseKestrel(k=>k.Listen(IPAddress.Loopback,0));host.StartServer();
        string address=Assert.Single(host.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses);
        using var client=new HttpClient { BaseAddress=new Uri(address) };
        foreach(var path in new[]{"/api/v1/agent/uninstall","/api/v1/agent/removal-result","/api/v1/agent/windows-audit-report"})
        {
            using var request=new HttpRequestMessage(HttpMethod.Post,path){Content=new StringContent("{}",Encoding.UTF8,"application/json")};
            request.Headers.Add("X-Client-Cert","synthetic-spoof");request.Headers.Add("X-Forwarded-Proto","https");
            using var response=await client.SendAsync(request,ct);
            Assert.Equal(HttpStatusCode.Unauthorized,response.StatusCode);Assert.Equal("no-store",response.Headers.CacheControl?.ToString());
            Assert.Equal("agent_mtls_required",JsonNode.Parse(await response.Content.ReadAsByteArrayAsync(ct))!["error"]!.GetValue<string>());
            using var malformed=await client.PostAsync(path,new StringContent("{",Encoding.UTF8,"application/json"),ct);
            Assert.Equal(HttpStatusCode.BadRequest,malformed.StatusCode);
            using var oversized=await client.PostAsync(path,new StringContent("{\"untrusted\":\""+new string('x',65536)+"\"}",Encoding.UTF8,"application/json"),ct);
            Assert.Equal(HttpStatusCode.RequestEntityTooLarge,oversized.StatusCode);
        }
        using(var fleet=await client.GetAsync("/api/v1/workstations/agents",ct))Assert.Equal(HttpStatusCode.Unauthorized,fleet.StatusCode);
        using(var feed=await client.GetAsync("/api/v1/agent/revocations?after=-1",ct))
        {Assert.Equal(HttpStatusCode.BadRequest,feed.StatusCode);Assert.Equal("invalid_revocation_cursor",JsonNode.Parse(await feed.Content.ReadAsByteArrayAsync(ct))!["error"]!.GetValue<string>());}
        foreach(string route in new[]{"/api/v1/workstations/agents","/api/v1/agent/revocations","/api/v1/agent/uninstall","/api/v1/agent/removal-result","/api/v1/agent/windows-audit-report"})
        foreach(string path in new[]{route+"/",route.Replace("/api/","/API/")})
        {
            using var request=new HttpRequestMessage(route.Contains("workstations")||route.EndsWith("revocations")?HttpMethod.Get:HttpMethod.Post,path){Content=new StringContent("not json",Encoding.UTF8,"application/json")};
            using var response=await client.SendAsync(request,ct);Assert.Equal(HttpStatusCode.NotImplemented,response.StatusCode);
        }
        Assert.Equal(0,database.Opens);
    }
}
