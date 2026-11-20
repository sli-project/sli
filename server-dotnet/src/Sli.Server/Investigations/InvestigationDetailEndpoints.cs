using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;

namespace Sli.Server.Investigations;

public static class InvestigationDetailEndpoints
{
    public static IServiceCollection AddInvestigationDetail(this IServiceCollection services)
    {
        services.TryAddScoped<IInvestigationDetailRepository,InvestigationDetailRepository>();
        services.TryAddScoped<IInvestigationRepository,InvestigationRepository>();
        services.TryAddScoped<IInvestigationVpnEvidence,InvestigationVpnEvidence>();
        services.TryAddScoped<IAccessFactsRepository,AccessFactsRepository>();
        return services;
    }
    public static IEndpointRouteBuilder MapInvestigationDetail(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/v1/investigations/{id}",InvestigationEndpoints.HandleDisabledAsync);
        endpoints.MapGet("/api/v1/investigations/{id}/{**tail}",InvestigationEndpoints.HandleDisabledAsync);
        return endpoints;
    }
    public static async Task HandleAsync(HttpContext context)
    {
        var ct=context.RequestAborted;
        try
        {
            var services=context.RequestServices; var failure=services.GetRequiredService<TransportGate>().CheckTransport(context);
            if(failure is not null) {await DomainHttp.WriteFailureAsync(context,failure,ct); return;}
            var policy=services.GetRequiredService<AuthRequestPolicy>(); Principal principal;
            if(policy.AuthRequired)
            {
                var auth=await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context,ct);
                if(!auth.Succeeded) {await DomainHttp.WriteFailureAsync(context,auth.Failure??new(401,"authentication_required"),ct);return;}
                principal=auth.Principal!;
                if(TransportGate.CheckViewerRole(principal) is {} roleFailure) {await DomainHttp.WriteFailureAsync(context,roleFailure,ct);return;}
            }
            else principal=new("",0,"operator");
            string raw=context.Features.Get<IHttpRequestFeature>()?.RawTarget is {Length:>0} target?target.Split('?',2)[0]:context.Request.Path.Value??"";
            var parts=raw.Split('/',StringSplitOptions.RemoveEmptyEntries);
            if(parts.Length<=3) {await AuthResponse.ErrorAsync(context,"invalid_investigation_id",400,ct,login:false);return;}
            var facts=await services.GetRequiredService<IAccessFactsRepository>().LoadAsync(principal,ct);
            var caps=new CapabilityComposer().Compose(facts);var access=new ReportEligibility().Compose(facts,caps);
            string? report=InvestigationList.ReportKey(access);
            if(report is null) {await DomainHttp.WriteAsync(context,new {error="report_not_assigned",required_report="investigations.workspace",required_action="view"},403,ct);return;}
            if(!caps.Capabilities.Contains("investigations.view") && !caps.ResourceCapabilities.Contains("investigations.view"))
            {await DomainHttp.WriteAsync(context,new {error="insufficient_capability",required_capability="investigations.view"},403,ct);return;}
            var identity=InvestigationIdentity.Parse(parts[3]);
            string? First(string name)=>context.Request.Query.TryGetValue(name,out var values)?values.FirstOrDefault(v=>!string.IsNullOrEmpty(v)):null;
            InvestigationEvidenceOptions? page=First("evidence_page")=="1"?new(First("event_after"),First("reference_after"),First("anchor_event_id")):null;
            if(page is null)
            {
                var groups=await services.GetRequiredService<IInvestigationRepository>().ResourceGroupsAsync(identity,ct);
                if(!InvestigationList.Allowed(access,report,groups)) throw new InvestigationException("not_found","Investigation resource was not found",404);
            }
            var vpn=services.GetRequiredService<IInvestigationVpnEvidence>();
            var row=await services.GetRequiredService<IInvestigationDetailRepository>().ReadAsync(identity,access,report,page,vpn,ct);
            var rendered=InvestigationCaseRenderer.Render(new(row,false),access,vpn);
            await DomainHttp.WriteAsync(context,rendered,200,ct);
        }
        catch(InvestigationException error) {await DomainHttp.WriteAsync(context,new {error=error.Code,message=error.Message},error.Status,ct);}
        catch(OperationCanceledException) when(ct.IsCancellationRequested) { }
        catch(Exception error) {if(context.Response.HasStarted) throw;await AuthResponse.UnexpectedAsync(context,error,ct,login:false);}
    }
}
