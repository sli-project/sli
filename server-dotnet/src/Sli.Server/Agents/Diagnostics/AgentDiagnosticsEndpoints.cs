using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http.Features;
using Sli.Server.Access;
using Sli.Server.Agents.Certificates;
using Sli.Server.Agents.ClientControl;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Registry;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;
using Sli.Server.Hosting;
using Sli.Server.Infrastructure;
namespace Sli.Server.Agents.Diagnostics;

public static class AgentDiagnosticsEndpoints
{
    public static IServiceCollection AddAgentDiagnostics(this IServiceCollection services)
    {services.AddScoped<AgentDiagnosticsService>();services.AddScoped<WorkstationAgentReader>();return services;}
    public static IEndpointRouteBuilder MapAgentDiagnosticsEndpoints(this IEndpointRouteBuilder endpoints)
    {
        foreach(string path in new[]{"/api/v1/workstations/agents","/api/v1/agent/revocations"})endpoints.MapGet(path,c=>HandleAsync(c,path));
        foreach(string path in new[]{"/api/v1/agent/uninstall","/api/v1/agent/removal-result","/api/v1/agent/windows-audit-report"})endpoints.MapPost(path,c=>HandleAsync(c,path));
        return endpoints;
    }
    internal static async Task HandleAsync(HttpContext context,string route)
    {
        var ct=context.RequestAborted;bool fleet=route=="/api/v1/workstations/agents";bool publicFeed=route=="/api/v1/agent/revocations";
        string raw=(context.Features.Get<IHttpRequestFeature>()?.RawTarget??context.Request.Path.Value??"").Split('?',2)[0];
        if(raw!=route){await DomainHttp.WriteAsync(context,new{error="not_implemented"},501,ct);return;}
        JsonNode? body=null;
        try{if(!fleet&&!publicFeed){using var doc=await AuthJsonBody.ReadAsync(context,ct);body=AgentClientJson.FromElement(doc.RootElement);}}
        catch(AuthInputException e){await DomainHttp.WriteAsync(context,new{error=e.Code},e.StatusCode,ct);return;}
        context.Response.Headers.CacheControl="no-store";
        try
        {
            var services=context.RequestServices;AccessFacts? facts=null;AccessDecision? access=null;
            if(fleet)
            {
                var failure=services.GetRequiredService<TransportGate>().CheckTransport(context);
                if(failure is not null){await DomainHttp.WriteFailureAsync(context,failure,ct);return;}
                var authenticated=await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context,ct);
                if(!authenticated.Succeeded){await DomainHttp.WriteFailureAsync(context,authenticated.Failure??new(401,"authentication_required"),ct);return;}
                failure=TransportGate.CheckViewerRole(authenticated.Principal!);
                if(failure is not null){await DomainHttp.WriteFailureAsync(context,failure,ct);return;}
                facts=await new AccessFactsRepository(services.GetRequiredService<IPostgresConnectionFactory>()).LoadAsync(authenticated.Principal!,ct);
                access=new ReportEligibility().Compose(facts,new CapabilityComposer().Compose(facts));
            }
            var peer=!fleet&&!publicFeed&&context.Request.IsHttps?await context.Connection.GetClientCertificateAsync(ct):null;
            if(!fleet&&!publicFeed&&(peer is null||services.GetService<AgentTlsTrust>() is null))throw new AgentCertificateException("agent_mtls_required",401);
            // Source validates the public cursor inside its operation and does not require a user or certificate.
            long after=publicFeed?AgentDiagnosticRules.RevocationCursor(context.Request.QueryString.Value??""):0;
            await using var db=await services.GetRequiredService<IPostgresConnectionFactory>().OpenAsync(ct);
            await using var tx=await db.BeginTransactionAsync(ct);JsonObject output;
            var diagnostics=services.GetRequiredService<AgentDiagnosticsService>();
            if(fleet)output=await services.GetRequiredService<WorkstationAgentReader>().ReadAsync(db,tx,facts!,access!,context.Request.QueryString.Value??"",ct);
            else if(publicFeed)output=await diagnostics.RevocationsAsync(db,tx,after,ct);
            else
            {
                var identity=services.GetRequiredService<AgentIdentityService>();AgentIdentity agent;
                if(route.EndsWith("/removal-result",StringComparison.Ordinal))agent=await identity.AuthenticateRemovalAsync(db,tx,peer!,ct);
                else if(route.EndsWith("/uninstall",StringComparison.Ordinal))
                {
                    if(body is not JsonObject o||o.Count!=0)throw new AgentControlException("agent_removal_invalid");
                    try{agent=await identity.AuthenticateAsync(db,tx,peer!,false,ct);}
                    catch(AgentCertificateException){agent=await identity.AuthenticateRemovalAsync(db,tx,peer!,ct);}
                }
                else agent=await identity.AuthenticateAsync(db,tx,peer!,false,ct);
                output=route.EndsWith("/uninstall",StringComparison.Ordinal)?await diagnostics.LocalUninstallAsync(db,tx,agent,ct)
                    :route.EndsWith("/removal-result",StringComparison.Ordinal)?await diagnostics.RemovalResultAsync(db,tx,agent,body,ct)
                    :await diagnostics.WindowsAuditAsync(db,tx,agent,body,ct);
            }
            await tx.CommitAsync(ct);await DomainHttp.WriteAsync(context,output,200,ct);
        }
        catch(AgentCertificateException e){await DomainHttp.WriteAsync(context,new{error=e.Code},e.Status,ct);}
        catch(AgentControlException e){await DomainHttp.WriteAsync(context,new{error=fleet&&e.Status==400?"workstation_request_invalid":e.Message},e.Status,ct);}
        catch(OperationCanceledException)when(ct.IsCancellationRequested){}
        catch(Exception)when(!context.Response.HasStarted){await DomainHttp.WriteAsync(context,new{error=fleet?"workstation_source_unavailable":"agent_service_unavailable"},503,ct);}
    }
}
