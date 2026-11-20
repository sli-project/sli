using Microsoft.Extensions.Logging;
using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Agents;
using Sli.Server.Agents.Control;
using Xunit;
namespace Sli.Server.Tests.Agents;
public sealed class AgentUpdateAdminEndpointTests
{
    [Fact]
    public async Task ExactAdminRoutesRequireRealPrincipalEvenWhenAuthIsDisabled()
    {
        var ct=TestContext.Current.CancellationToken;
        foreach(string required in new[]{"0","1"}) {
            using var host=new WebApplicationFactory<Program>().WithWebHostBuilder(b=>b.ConfigureAppConfiguration((_,cfg)=>cfg.AddInMemoryCollection(new Dictionary<string,string?> {
                ["Sli:AgentMtlsCaFile"]="",["urls"] = "http://127.0.0.1:0", ["Sli:TrustedProxies"]="",["Sli:AuthRequired"]=required,["Sli:AllowUnauthenticated"]="1",["Sli:OperatorToken"]="",["Sli:AuthAllowInsecureHttp"]="1",["Sli:OwnerSetup"]="0" })).ConfigureServices(s=>s.AddSingleton<IPostgresConnectionFactory,RefuseDatabase>())).WithWebHostBuilder(b => b.ConfigureLogging(logging => logging.ClearProviders()).ConfigureServices(services => {
            foreach (var worker in services.Where(d => d.ServiceType == typeof(Microsoft.Extensions.Hosting.IHostedService)
                && (d.ImplementationType == typeof(Sli.Server.Workspace.DashboardWarmupService)
                    || d.ImplementationType == typeof(Sli.Server.Legacy.LegacyJobWorker)
                    || d.ImplementationType == typeof(Sli.Server.Legacy.LegacyScheduler)
                    || d.ImplementationType == typeof(Sli.Server.Legacy.LegacyPostCollectionHostedService))).ToArray())
                services.Remove(worker);
        }));
            host.UseKestrel(k=>k.Listen(IPAddress.Loopback,0));host.StartServer();
            using var client=new HttpClient { BaseAddress=new Uri(Assert.Single(host.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses)) };
            foreach(var (method,path) in new[]{("POST","/api/v1/admin/agents/restore"),("GET","/api/v1/admin/agent-packages"),("POST","/api/v1/admin/agent-packages"),("POST","/api/v1/admin/agents/update-policy"),("GET","/api/v1/admin/agent-update-waves"),("POST","/api/v1/admin/agent-update-waves"),("POST","/api/v1/admin/agent-update-waves/stop")}) {
                using var request=new HttpRequestMessage(new HttpMethod(method),path);if(method=="POST")request.Content=new StringContent("{",Encoding.UTF8,"application/json");
                using var response=await client.SendAsync(request,ct);Assert.Equal(HttpStatusCode.Unauthorized,response.StatusCode);
                Assert.Equal("authentication_required",JsonNode.Parse(await response.Content.ReadAsByteArrayAsync(ct))!["error"]!.GetValue<string>());
            }
            using var wrong=await client.GetAsync("/API/v1/admin/agent-update-waves/",ct);Assert.Equal(HttpStatusCode.NotImplemented,wrong.StatusCode);
            using var origin=new HttpRequestMessage(HttpMethod.Post,"/api/v1/admin/agent-packages");origin.Headers.Add("Origin","https://foreign.example");origin.Content=new StringContent("{",Encoding.UTF8,"application/json");
            using var denied=await client.SendAsync(origin,ct);Assert.Equal(HttpStatusCode.Forbidden,denied.StatusCode);
        }
    }
    [Fact]
    public async Task UploadReaderEnforcesExactSourceMediaLengthAndTransferCoding()
    {
        static DefaultHttpContext Input(long? length,string type="application/zip",string transfer="",byte[]? body=null) {
            var context=new DefaultHttpContext();context.Request.ContentLength=length;context.Request.ContentType=type;context.Request.Headers.TransferEncoding=transfer;context.Request.Body=new MemoryStream(body??[1,2,3]);return context;
        }
        Assert.Equal(new byte[]{1,2,3},await AgentUpdateAdministrationEndpoints.ReadUploadAsync(Input(3)));
        foreach(var context in new[]{Input(null),Input(0),Input(268435457),Input(3,"application/zip; charset=utf-8"),Input(3,"application/zip","chunked"),Input(4)})
            Assert.Equal("agent_package_invalid",(await Assert.ThrowsAsync<AgentControlException>(()=>AgentUpdateAdministrationEndpoints.ReadUploadAsync(context))).Message);
    }
    private sealed class RefuseDatabase:IPostgresConnectionFactory
    {public Task<NpgsqlConnection> OpenAsync(CancellationToken ct)=>throw new InvalidOperationException("Unexpected database access before authority");}
}
