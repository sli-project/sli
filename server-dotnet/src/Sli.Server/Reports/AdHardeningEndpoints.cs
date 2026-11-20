using System.Globalization;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;

namespace Sli.Server.Reports;

public static class AdHardeningEndpoints
{
    public static IServiceCollection AddAdHardening(this IServiceCollection services){services.TryAddScoped<IAccessFactsRepository,AccessFactsRepository>();services.AddScoped<IAdHardeningSource,AdHardeningSource>();return services;}
    public static IEndpointRouteBuilder MapAdHardening(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/v2/reports/security.problems/data",HandleAsync);return endpoints;
    }
    internal static DomainGrant Domains(AccessDecision access,IReadOnlySet<string>? fields=null)=>new ReportScopeResolver().PermittedDomains(access,[new("ad-hardening","security.queue","domain",(fields??new HashSet<string>()).Append("security").ToHashSet(),new HashSet<string>(),null,false)]);
    public static async Task HandleAsync(HttpContext context)
    {
        if (context.Request.Query["tab"].FirstOrDefault(s => !string.IsNullOrEmpty(s)) != "ad-hardening")
        { await Sli.Server.Reporting.V2.ReportV2Endpoints.HandleAsync(context); return; }
        var ct=context.RequestAborted;
        try{
            var services=context.RequestServices;var failure=services.GetRequiredService<TransportGate>().CheckTransport(context);if(failure!=null){await DomainHttp.WriteFailureAsync(context,failure,ct);return;}
            var auth=await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context,ct);if(!auth.Succeeded){await DomainHttp.WriteFailureAsync(context,auth.Failure??new(401,"authentication_required"),ct);return;}
            if(TransportGate.CheckViewerRole(auth.Principal!) is {} roleFailure){await DomainHttp.WriteFailureAsync(context,roleFailure,ct);return;}
            var facts=await services.GetRequiredService<IAccessFactsRepository>().LoadAsync(auth.Principal!,ct);var access=new ReportEligibility().Compose(facts,new CapabilityComposer().Compose(facts));
            var report=access.Reports.FirstOrDefault(r=>r.ReportKey=="security.queue"&&r.Allowed);
            if(report==null){await DomainHttp.WriteAsync(context,new{error="report_not_assigned",required_report="security.queue",required_action="view"},403,ct);return;}
            if(!report.Grants.Any(g=>g.AllowedActions.Contains("view")&&g.FieldCategories.Contains("security"))){await DomainHttp.WriteAsync(context,new{error="report_field_categories_not_allowed"},403,ct);return;}
            string? First(string key)=>context.Request.Query[key].FirstOrDefault(s=>!string.IsNullOrEmpty(s));
            foreach(string key in new[]{"cursor","status","id","entity_id","risk","cohort","created_from","created_to","time_from","time_to","show_suppressed"})if(First(key)!=null)throw new ArgumentException("report_parameter_invalid:ad-hardening");
            var grant=Domains(access);long[]? domains=grant.Kind==DomainGrantKind.All?null:grant.DomainIds.Order().ToArray();
            if(First("domain") is {} selected&&selected!="all"){
                var values=selected.Split(',');if(values.Length>100||values.Any(s=>!long.TryParse(s,NumberStyles.None,CultureInfo.InvariantCulture,out var id)||id<=0))throw new ArgumentException("report_parameter_invalid:domain");
                var ids=values.Select(s=>long.Parse(s,CultureInfo.InvariantCulture)).Distinct().ToArray();domains=domains==null?ids:ids.Intersect(domains).ToArray();
            }
            string? query=First("q"),severity=First("severity"),rule=First("rule_code");if(query?.Length>512||severity!=null&&severity is not ("high" or "medium" or "info"))throw new ArgumentException("report_parameter_invalid:ad-hardening");
            if(query!=null){var identities=Domains(access,new HashSet<string>{"identity_basic"});bool allowed=domains==null?identities.Kind==DomainGrantKind.All:identities.Kind==DomainGrantKind.All||domains.All(identities.DomainIds.Contains);if(!allowed){await DomainHttp.WriteAsync(context,new{error="report_field_categories_not_allowed"},403,ct);return;}}
            var snapshots=await services.GetRequiredService<IAdHardeningSource>().LoadAsync(domains,ct);
            bool Fields(long domain,string category)=>ResourceAccessDecisions.ReportAction(access,"security.queue","view",[[new("domain",domain)]],new HashSet<string>{"security",category}).Allowed;
            await DomainHttp.WriteAsync(context,AdHardeningReport.Render(snapshots,DateTimeOffset.UtcNow,DomainHttp.SelectEnglish(context.Request.Headers.AcceptLanguage.ToString()),severity,query,rule,Fields),200,ct);
        }
        catch(ArgumentException e){await DomainHttp.WriteAsync(context,new{error=e.Message.StartsWith("report_parameter_invalid",StringComparison.Ordinal)?e.Message:"report_parameter_invalid"},400,ct);}
        catch(DomainScopeCompositionException){await DomainHttp.WriteAsync(context,new{error="invalid_scope_dimension"},400,ct);}
        catch(OperationCanceledException)when(ct.IsCancellationRequested){}
        catch(Exception e){if(context.Response.HasStarted)throw;await AuthResponse.UnexpectedAsync(context,e,ct,login:false);}
    }
}
