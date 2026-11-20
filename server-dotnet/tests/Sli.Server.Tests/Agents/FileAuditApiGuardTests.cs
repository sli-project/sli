using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Sli.Server.Agents.FileAudit;
using Xunit;
namespace Sli.Server.Tests.Agents;
public class FileAuditApiGuardTests
{
    [Fact]
    public async Task ReportWithoutPeerCertificateCannotReachIngest()
    {
        var builder=WebApplication.CreateBuilder();builder.WebHost.UseTestServer();builder.Services.AddFileAuditControl();
        await using var app=builder.Build(); app.Use(async (ctx,next)=> { ctx.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpRequestFeature>()!.RawTarget=ctx.Request.Path; await next(); }); app.MapFileAuditControlEndpoints();await app.StartAsync(TestContext.Current.CancellationToken);
        var response=await app.GetTestClient().PostAsync("/api/v1/agent/file-audit-report",new StringContent("{}",System.Text.Encoding.UTF8,"application/json"),TestContext.Current.CancellationToken);
        Assert.Equal(System.Net.HttpStatusCode.Unauthorized,response.StatusCode);
        Assert.Contains("agent_mtls_required",await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }
}

