using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;
namespace Sli.Server.Workstations;

public static class WorkstationEndpoints
{
    public static IServiceCollection AddWorkstationReports(this IServiceCollection services)
    {
        services.TryAddScoped<IAccessFactsRepository,AccessFactsRepository>();
        services.TryAddScoped<IWorkstationReports,WorkstationReports>();return services;
    }
    public static IEndpointRouteBuilder MapWorkstationReports(this IEndpointRouteBuilder endpoints)
    {
        // The native workspace owns overview. Retained family readers and their
        // independent history adapters remain deliberately unavailable.
        foreach(string key in WorkstationReportContract.Keys.Where(key=>key!="workstations.overview"))
        {
            endpoints.MapGet("/api/v2/reports/"+key,c=>Handle(c,key,"declaration"));
            endpoints.MapGet("/api/v2/reports/"+key+"/data",c=>Handle(c,key,"data"));
            endpoints.MapGet("/api/v2/reports/"+key+"/rows/{id}/detail",c=>Handle(c,key,"detail"));
            endpoints.MapGet("/api/v2/reports/"+key+"/export.csv",c=>Handle(c,key,"export"));
        }
        return endpoints;
    }
    static async Task Handle(HttpContext context,string key,string action)
    {
        var ct=context.RequestAborted;context.Response.Headers.CacheControl="no-store";
        try
        {
            var s=context.RequestServices;
            if(s.GetRequiredService<TransportGate>().CheckTransport(context) is {} transport){await DomainHttp.WriteFailureAsync(context,transport,ct);return;}
            Principal principal;
            if(s.GetRequiredService<AuthRequestPolicy>().AuthRequired)
            {
                var auth=await s.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context,ct);
                if(!auth.Succeeded){await DomainHttp.WriteFailureAsync(context,auth.Failure??new(401,"authentication_required"),ct);return;}
                principal=auth.Principal!;
                if(TransportGate.CheckViewerRole(principal) is {} failure){await DomainHttp.WriteFailureAsync(context,failure,ct);return;}
            }
            else principal=new("",0,"operator");
            var facts=await s.GetRequiredService<IAccessFactsRepository>().LoadAsync(principal,ct);
            var access=new ReportEligibility().Compose(facts,new CapabilityComposer().Compose(facts));
            if(!access.Reports.Any(r=>r.ReportKey==key&&r.Allowed))
            {await DomainHttp.WriteAsync(context,new{error="report_access_denied"},403,ct);return;}
            if(action=="export")throw new WorkstationException("report_export_not_available",404);
            if(action=="detail"&&key is "workstations.logons" or "workstations.protection")throw new WorkstationException("report_detail_not_available",404);
            if(action=="declaration"){await DomainHttp.WriteAsync(context,new{error="module_disabled",state="disabled"},503,ct);return;}
            WorkstationReportContract.Admit(access,key);
            var request=WorkstationReportContract.Parse(key,context.Request.Query,context.Request.RouteValues["id"]?.ToString());
            if(action=="detail")request=request with{Limit=Math.Min(request.Limit,50)};
            await DomainHttp.WriteAsync(context,new{error="module_disabled",state="disabled"},503,ct);
        }
        catch(WorkstationException e)
        {
            if(e.Status==403)await DomainHttp.WriteAsync(context,new{error=e.Message,state="denied",reason=e.Message,access=new{allowed=false,hidden_categories=Array.Empty<string>(),reason=e.Message}},403,ct);
            else await DomainHttp.WriteAsync(context,new{error=e.Message},e.Status,ct);
        }
        catch(Sli.Server.Agents.Control.AgentControlException e){await DomainHttp.WriteAsync(context,new{error=e.Message,state="denied",reason=e.Message},e.Status,ct);}
        catch(PostgresException e)when(e.SqlState=="57014"){await DomainHttp.WriteAsync(context,new{error="report_read_timeout",state="unavailable"},503,ct);}
        catch(OperationCanceledException)when(ct.IsCancellationRequested){}
        catch(Exception)when(!context.Response.HasStarted){await DomainHttp.WriteAsync(context,new{error="workstation_source_unavailable",state="error"},503,ct);}
    }
}
