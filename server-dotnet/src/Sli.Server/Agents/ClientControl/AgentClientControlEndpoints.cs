using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http.Features;
using Sli.Server.Agents.Certificates;
using Sli.Server.Agents.ClientControl;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Registry;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;
using Sli.Server.Hosting;
using Sli.Server.Infrastructure;
namespace Sli.Server.Agents;

public static class AgentClientControlEndpoints
{
    public static IServiceCollection AddAgentClientControl(this IServiceCollection services)
    {services.AddScoped<AgentClientControlService>();return services;}
    public static IEndpointRouteBuilder MapAgentClientControlEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/v1/agent/identity",c=>HandleAsync(c,false));
        endpoints.MapPost("/api/v1/agent/policy-report",c=>HandleAsync(c,true));return endpoints;
    }
    private static async Task HandleAsync(HttpContext context,bool report)
    {
        var ct=context.RequestAborted;string route=report?"/api/v1/agent/policy-report":"/api/v1/agent/identity";
        string raw=(context.Features.Get<IHttpRequestFeature>()?.RawTarget ?? context.Request.Path.Value ?? "").Split('?',2)[0];
        if(raw!=route){await DomainHttp.WriteAsync(context,new { error="not_implemented" },501,ct);return;}
        JsonNode? body=null;
        try { if(report){using var doc=await AuthJsonBody.ReadAsync(context,ct);body=AgentClientJson.FromElement(doc.RootElement);} }
        catch(AuthInputException error){await DomainHttp.WriteAsync(context,new { error=error.Code },error.StatusCode,ct);return;}
        context.Response.Headers.CacheControl="no-store";
        try {
            var peer=context.Request.IsHttps?await context.Connection.GetClientCertificateAsync(ct):null;
            if(peer is null || context.RequestServices.GetService<AgentTlsTrust>() is null)throw new AgentCertificateException("agent_mtls_required",401);
            var services=context.RequestServices;
            await using var db=await services.GetRequiredService<IPostgresConnectionFactory>().OpenAsync(ct);
            await using var tx=await db.BeginTransactionAsync(ct);
            var auth=services.GetRequiredService<AgentIdentityService>();var service=services.GetRequiredService<AgentClientControlService>();JsonObject result;
            if(report) {
                if (body is JsonObject reportBody && reportBody.ContainsKey("dc_identity"))
                    await AgentEnrollmentService.LockRegistrationAsync(db, tx, ct);
                var agent=await auth.AuthenticateAsync(db,tx,peer,false,ct);
                result=await service.ReportAsync(db,tx,agent,body,ct);
            } else {
                await AgentClientControlService.LockUpdateWavesAsync(db,tx,ct);AgentIdentity agent;
                try { agent=await auth.AuthenticateAsync(db,tx,peer,false,ct); }
                catch(AgentCertificateException) {
                    agent=await auth.AuthenticateRemovalAsync(db,tx,peer,ct);
                    result=await AgentClientControlService.RemovalCommandAsync(db,tx,agent,ct);
                    await tx.CommitAsync(ct);await DomainHttp.WriteAsync(context,result,200,ct);return;
                }
                result=await service.CheckInAsync(db,tx,agent,ct);
            }
            await tx.CommitAsync(ct);await DomainHttp.WriteAsync(context,result,200,ct);
        }
        catch(AgentCertificateException error){await DomainHttp.WriteAsync(context,new { error=error.Code },error.Status,ct);}
        catch(AgentControlException error){await DomainHttp.WriteAsync(context,new { error=error.Message },error.Status,ct);}
        catch(OperationCanceledException) when(ct.IsCancellationRequested){}
        catch(Exception) when(!context.Response.HasStarted){await DomainHttp.WriteAsync(context,new { error="agent_service_unavailable" },503,ct);}
    }
}
