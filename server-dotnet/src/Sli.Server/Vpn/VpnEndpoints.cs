using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;

namespace Sli.Server.Vpn;

public static class VpnEndpoints
{
    public static readonly string[] Operations=["session-sources","sessions","sessions/evidence","authorizations","failed-authorizations/series","windows-authentication","windows-authentication-sources"];
    public static IServiceCollection AddVpn(this IServiceCollection services)
    { services.TryAddScoped<IAccessFactsRepository,AccessFactsRepository>();services.TryAddScoped<IVpnStore,PostgresVpnStore>();return services; }
    public static IEndpointRouteBuilder MapVpn(this IEndpointRouteBuilder endpoints)
    {
        foreach(string operation in Operations) endpoints.MapGet("/api/v1/reports/vpn.audit/"+operation,HandleAsync);
        foreach(string report in new[]{"vpn.accounts","vpn.connections"})
        {
            endpoints.MapGet("/api/v2/reports/"+report,HandleAsync);
            endpoints.MapGet("/api/v2/reports/"+report+"/data",HandleAsync);
            endpoints.MapGet("/api/v2/reports/"+report+"/export.csv",HandleAsync);
            endpoints.MapGet("/api/v2/reports/"+report+"/rows/{row_id}/detail",HandleAsync);
        }
        return endpoints;
    }
    public static async Task HandleAsync(HttpContext context)
    {
        var ct=context.RequestAborted;
        try
        {
            var services=context.RequestServices;var transport=services.GetRequiredService<TransportGate>().CheckTransport(context);
            if(transport is not null) { await DomainHttp.WriteFailureAsync(context,transport,ct);return; }
            Principal principal;
            if(services.GetRequiredService<AuthRequestPolicy>().AuthRequired)
            {
                var auth=await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context,ct);
                if(!auth.Succeeded) { await DomainHttp.WriteFailureAsync(context,auth.Failure??new(401,"authentication_required"),ct);return; }
                principal=auth.Principal!;if(TransportGate.CheckViewerRole(principal) is {} role) { await DomainHttp.WriteFailureAsync(context,role,ct);return; }
            }
            else principal=new("",0,"operator");
            var access=new VpnAccess(await services.GetRequiredService<IAccessFactsRepository>().LoadAsync(principal,ct));
            string path=context.Request.Path.Value??"";bool v2=path.StartsWith("/api/v2/",StringComparison.Ordinal);
            if(!v2 && access.Capabilities.Decide("reports.catalog") is {Allowed:false} denied)
            { await DomainHttp.WriteAsync(context,new {error=denied.Reason,required_capability="reports.catalog"},403,ct);return; }
            if(!access.Assigned())
            { await DomainHttp.WriteAsync(context,new {error="report_access_denied"},403,ct);return; }
            if(v2 && !access.LegacyExecutable) throw new VpnPermissionException("report_scope_not_executable");
            await DomainHttp.WriteAsync(context,new {error="module_disabled",state="disabled"},503,ct);
        }
        catch(VpnInputException e) { await DomainHttp.WriteAsync(context,new {error=e.Message},e.Message is "vpn_session_source_domain_not_registered" or "vpn_session_evidence_session_not_found"?404:400,ct); }
        catch(VpnPermissionException e) {await DomainHttp.WriteAsync(context,new {error=e.Message,state="denied",reason=e.Message},403,ct);}
        catch(OverflowException) { await DomainHttp.WriteAsync(context,new {error="invalid_integer"},400,ct); }
        catch(OperationCanceledException) when(ct.IsCancellationRequested) { }
        catch(Exception e) when(VpnAuthorizations.IsTimeout(e)) { await DomainHttp.WriteAsync(context,new {error="report_read_timeout",state="unavailable"},503,ct); }
        catch(Exception e) { if(context.Response.HasStarted) throw;await AuthResponse.UnexpectedAsync(context,e,ct,login:false); }
    }
}
