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
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using Sli.Server.Infrastructure;
using Xunit;

namespace Sli.Server.Tests;

public sealed class AgentTemplateEndpointTests
{
    [Fact]
    public async Task RealTemplateRoutesKeepAuthenticationInAuthOffAndGuardBeforeBodyOrDatabase()
    {
        var ct=TestContext.Current.CancellationToken;
        foreach(bool required in new[]{true,false})
        {
            var database=new RefuseDatabase();
            using var host=new WebApplicationFactory<Program>().WithWebHostBuilder(b=>
            {
                b.ConfigureAppConfiguration((_,cfg)=>cfg.AddInMemoryCollection(new Dictionary<string,string?>{
                    ["Sli:AgentMtlsCaFile"]="",["urls"] = "http://127.0.0.1:0", ["Sli:TrustedProxies"]="",["Sli:AuthRequired"]=required?"1":"0",
                    ["Sli:AllowUnauthenticated"]=required?"0":"1",
                    ["Sli:AuthAllowInsecureHttp"]="1",["Sli:OwnerSetup"]="0",["Sli:OperatorToken"]="synthetic-template-operator"}));
                b.ConfigureServices(s=>{s.RemoveAll<IPostgresConnectionFactory>();s.AddSingleton<IPostgresConnectionFactory>(database);});
            }).WithWebHostBuilder(b => b.ConfigureLogging(logging => logging.ClearProviders()).ConfigureServices(services => {
            foreach (var worker in services.Where(d => d.ServiceType == typeof(Microsoft.Extensions.Hosting.IHostedService)
                && (d.ImplementationType == typeof(Sli.Server.Workspace.DashboardWarmupService)
                    || d.ImplementationType == typeof(Sli.Server.Agents.Registry.AgentRegistrationReconciliation)
                    || d.ImplementationType == typeof(Sli.Server.Legacy.LegacyJobWorker)
                    || d.ImplementationType == typeof(Sli.Server.Legacy.LegacyScheduler)
                    || d.ImplementationType == typeof(Sli.Server.Legacy.LegacyPostCollectionHostedService))).ToArray())
                services.Remove(worker);
        }));
            host.UseKestrel(k=>k.Listen(IPAddress.Loopback,0));host.StartServer();
            using var client=new HttpClient{BaseAddress=new Uri(Assert.Single(host.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses))};
            using(var get=await client.GetAsync("/api/v1/admin/agent-templates?ignored=1",ct))Assert.Equal(HttpStatusCode.Unauthorized,get.StatusCode);
            using(var request=new HttpRequestMessage(HttpMethod.Post,"/api/v1/admin/agent-templates"))
            {request.Headers.Add("X-ADLog-Operator-Token","synthetic-template-operator");request.Content=new StringContent("{",Encoding.UTF8,"application/json");using var response=await client.SendAsync(request,ct);Assert.Equal(HttpStatusCode.Unauthorized,response.StatusCode);}
            using(var request=new HttpRequestMessage(HttpMethod.Post,"/api/v1/admin/agent-templates"))
            {request.Headers.Add("Origin","https://synthetic-foreign.invalid");request.Content=new StringContent("{",Encoding.UTF8,"application/json");using var response=await client.SendAsync(request,ct);Assert.Equal(HttpStatusCode.Forbidden,response.StatusCode);Assert.Equal("cross_origin_request_rejected",JsonNode.Parse(await response.Content.ReadAsByteArrayAsync(ct))!["error"]!.GetValue<string>());}
            if(!required)
            {using var response=await client.PostAsync("/api/v1/admin/agent-templates",new StringContent("{",Encoding.UTF8,"application/json"),ct);Assert.Equal(HttpStatusCode.Unauthorized,response.StatusCode);Assert.Equal("operator_token_required",JsonNode.Parse(await response.Content.ReadAsByteArrayAsync(ct))!["error"]!.GetValue<string>());}
            foreach(string path in new[]{"/API/v1/admin/agent-templates","/api/v1/admin/agent-templates/"})
            {using var response=await client.PostAsync(path,new StringContent("{",Encoding.UTF8,"application/json"),ct);Assert.Equal(HttpStatusCode.NotImplemented,response.StatusCode);}
            Assert.Equal(0,database.Calls);
        }
    }
    private sealed class RefuseDatabase:IPostgresConnectionFactory
    {public int Calls;public Task<NpgsqlConnection> OpenAsync(CancellationToken ct){Calls++;throw new InvalidOperationException("Unexpected template database access before admission");}}
}
