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
using Sli.Server.Infrastructure;
using Npgsql;
using Sli.Server.Auth.Lifecycle;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace Sli.Server.Tests;

public sealed class AgentGroupEndpointTests
{
    [Fact]
    public async Task GroupEnrollmentReadsBodyBeforeActualTlsAndRejectsPathOrHeaderSpoofs()
    {
        var ct=TestContext.Current.CancellationToken;
        var database=new RefuseDatabase();
        using var host=new WebApplicationFactory<Program>().WithWebHostBuilder(b=>{
            b.ConfigureAppConfiguration((_,cfg)=>cfg.AddInMemoryCollection(new Dictionary<string,string?> {
            ["Sli:AgentMtlsCaFile"]="",["urls"] = "http://127.0.0.1:0", ["Sli:TrustedProxies"]="",["Sli:AuthRequired"]="1",["Sli:AuthAllowInsecureHttp"]="1",["Sli:OwnerSetup"]="0" }));
            b.ConfigureServices(s=>{s.RemoveAll<IPostgresConnectionFactory>();s.AddSingleton<IPostgresConnectionFactory>(database);});}).WithWebHostBuilder(b => b.ConfigureLogging(logging => logging.ClearProviders()).ConfigureServices(services => {
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
        using var client=new HttpClient{BaseAddress=new Uri(address)};
        foreach(var (body,status,error) in new[]{("{}",401,"agent_tls_required"),("{",400,"invalid_json"),("[]",400,"json_object_required"),("{\"x\":\""+new string('a',65536)+"\"}",413,"request_body_too_large")})
        {
            using var request=new HttpRequestMessage(HttpMethod.Post,"/api/v1/agent/group-enroll");request.Headers.Add("X-Forwarded-Proto","https");request.Headers.Add("X-Client-Cert","synthetic-spoof");request.Content=new StringContent(body,Encoding.UTF8,"application/json");
            using var response=await client.SendAsync(request,ct);Assert.Equal(status,(int)response.StatusCode);
            Assert.Equal(error,JsonNode.Parse(await response.Content.ReadAsByteArrayAsync(ct))!["error"]!.GetValue<string>());
            if(status==401)Assert.Equal("no-store",response.Headers.CacheControl?.ToString());
        }
        foreach(string path in new[]{"/API/v1/agent/group-enroll","/api/v1/agent/group-enroll/","/API/v1/admin/agent-group-tokens","/api/v1/admin/agent-onboarding/approve/"})
        {using var response=await client.PostAsync(path,new StringContent("{",Encoding.UTF8,"application/json"),ct);Assert.Equal(HttpStatusCode.NotImplemented,response.StatusCode);}
        foreach(string path in new[]{"/api/v1/admin/agent-group-tokens","/api/v1/admin/agent-group-tokens/revoke","/api/v1/admin/agent-group-requests","/api/v1/admin/agent-group-requests/approve","/api/v1/admin/agent-onboarding/approve"})
        {using var response=await client.PostAsync(path,new StringContent("{",Encoding.UTF8,"application/json"),ct);Assert.Equal(HttpStatusCode.Unauthorized,response.StatusCode);}
        Assert.Equal(0,database.Calls);
    }
    [Fact]
    public async Task LargerAuthorizedAttestationParserRetainsOrdinaryBodyBound()
    {
        var bytes=Encoding.UTF8.GetBytes("{\"evidence\":\""+new string('x',70000)+"\"}");
        DefaultHttpContext Context(){var c=new DefaultHttpContext();c.Request.ContentLength=bytes.Length;c.Request.ContentType="application/json";c.Request.Body=new MemoryStream(bytes);return c;}
        Assert.Equal(413,(await Assert.ThrowsAsync<AuthInputException>(()=>AuthJsonBody.ReadAsync(Context(),TestContext.Current.CancellationToken))).StatusCode);
        using var read=await AuthJsonBody.ReadAsync(Context(),TestContext.Current.CancellationToken,512*1024);Assert.Equal(70000,read.RootElement.GetProperty("evidence").GetString()!.Length);
    }
    private sealed class RefuseDatabase:IPostgresConnectionFactory
    {public int Calls;public Task<NpgsqlConnection> OpenAsync(CancellationToken ct){Calls++;throw new InvalidOperationException("Unexpected database access before admission");}}
}
