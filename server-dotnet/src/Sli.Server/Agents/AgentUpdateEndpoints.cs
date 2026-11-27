using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http.Features;
using Sli.Server.Agents.Certificates;
using Sli.Server.Agents.ClientControl;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Registry;
using Sli.Server.Agents.Updates;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;
using Sli.Server.Hosting;
using Sli.Server.Infrastructure;
namespace Sli.Server.Agents;

public static class AgentUpdateEndpoints
{
    public static IServiceCollection AddAgentUpdates(this IServiceCollection services)
    {services.AddScoped<AgentUpdateService>();return services;}
    public static IEndpointRouteBuilder MapAgentUpdateEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/v1/agent/package",c=>HandleAsync(c,false));
        endpoints.MapPost("/api/v1/agent/update-result",c=>HandleAsync(c,true));return endpoints;
    }
    private static async Task HandleAsync(HttpContext context,bool report)
    {
        var ct=context.RequestAborted;string route=report?"/api/v1/agent/update-result":"/api/v1/agent/package";
        string raw=(context.Features.Get<IHttpRequestFeature>()?.RawTarget ?? context.Request.Path.Value ?? "").Split('?',2)[0];
        if(raw!=route){await DomainHttp.WriteAsync(context,new { error="not_implemented" },501,ct);return;}
        JsonObject? body=null;
        try {if(report){using var document=await AuthJsonBody.ReadAsync(context,ct);body=AgentClientJson.FromElement(document.RootElement)!.AsObject();}}
        catch(AuthInputException error){await DomainHttp.WriteAsync(context,new { error=error.Code },error.StatusCode,ct);return;}
        context.Response.Headers.CacheControl="no-store";
        try {
            var peer=context.Request.IsHttps?await context.Connection.GetClientCertificateAsync(ct):null;
            if(peer is null || context.RequestServices.GetService<AgentTlsTrust>() is null)throw new AgentCertificateException("agent_mtls_required",401);
            var services=context.RequestServices;
            await using var db=await services.GetRequiredService<IPostgresConnectionFactory>().OpenAsync(ct);
            await using var tx=await db.BeginTransactionAsync(ct);
            await AgentClientControlService.LockUpdateWavesAsync(db,tx,ct);
            var agent=await services.GetRequiredService<AgentIdentityService>().AuthenticateAsync(db,tx,peer,false,ct);
            var service=services.GetRequiredService<AgentUpdateService>();
            if(report) {
                var result=await service.ReportAsync(db,tx,agent,body!,ct);await tx.CommitAsync(ct);await DomainHttp.WriteAsync(context,result,200,ct);
            } else {
                var package=await service.DownloadPackageAsync(db,tx,agent,AgentUpdateInput.PackageQuery(context.Request.QueryString.Value??""),ct);
                await using var content=package.Content;
                await tx.CommitAsync(ct);
                context.Response.StatusCode=200;context.Response.ContentType=package.ContentType;context.Response.ContentLength=content.Length;
                // Source sends the complete assigned archive, ignoring Range and
                // conditional headers. No bytes or success headers before commit.
                await content.CopyToAsync(context.Response.Body,ct);
            }
        }
        catch(AgentCertificateException error){await DomainHttp.WriteAsync(context,new { error=error.Code },error.Status,ct);}
        catch(AgentControlException error){await DomainHttp.WriteAsync(context,new { error=error.Message },error.Status,ct);}
        catch(OperationCanceledException) when(ct.IsCancellationRequested){}
        catch(Exception) when(!context.Response.HasStarted){context.Response.ContentLength=null;await DomainHttp.WriteAsync(context,new { error="agent_service_unavailable" },503,ct);}
    }
}
