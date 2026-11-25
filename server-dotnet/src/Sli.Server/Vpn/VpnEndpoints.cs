using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;
using Sli.Server.Reporting.V2;

namespace Sli.Server.Vpn;

public static class VpnEndpoints
{
    private const string ConnectionsPath = "/api/v2/reports/vpn.connections";
    private static readonly HashSet<string> AccountingTabs = ["employees", "daily", "departments"];
    private static readonly HashSet<string> AccountingFilters = ["domain", "period", "q", "department", "status"];
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
            var facts = await services.GetRequiredService<IAccessFactsRepository>().LoadAsync(principal, ct);
            var access = new VpnAccess(facts);
            string path=context.Request.Path.Value??"";bool v2=path.StartsWith("/api/v2/",StringComparison.Ordinal);
            if(!v2 && access.Capabilities.Decide("reports.catalog") is {Allowed:false} denied)
            { await DomainHttp.WriteAsync(context,new {error=denied.Reason,required_capability="reports.catalog"},403,ct);return; }
            if(!access.Assigned())
            { await DomainHttp.WriteAsync(context,new {error="report_access_denied"},403,ct);return; }
            if(v2 && !access.LegacyExecutable) throw new VpnPermissionException("report_scope_not_executable");
            var store = services.GetRequiredService<IVpnStore>();
            bool definition = path == ConnectionsPath;
            if ((definition || path == ConnectionsPath + "/data") && store.AccountingConfigured)
            {
                await ReadAccountingConnections(context, store, access, facts, definition, ct);
                return;
            }
            await DomainHttp.WriteAsync(context,new {error="module_disabled",state="disabled"},503,ct);
        }
        catch(ReportRequestException e) { await DomainHttp.WriteAsync(context, new { error = e.Message }, e.Status, ct); }
        catch(VpnInputException e) { await DomainHttp.WriteAsync(context,new {error=e.Message},e.Message is "vpn_session_source_domain_not_registered" or "vpn_session_evidence_session_not_found"?404:400,ct); }
        catch(VpnPermissionException e) {await DomainHttp.WriteAsync(context,new {error=e.Message,state="denied",reason=e.Message},403,ct);}
        catch(NpgsqlException) { await DomainHttp.WriteAsync(context, new { error = "vpn_source_unavailable", state = "unavailable" }, 503, ct); }
        catch(OverflowException) { await DomainHttp.WriteAsync(context,new {error="invalid_integer"},400,ct); }
        catch(OperationCanceledException) when(ct.IsCancellationRequested) { }
        catch(Exception e) when(VpnAuthorizations.IsTimeout(e)) { await DomainHttp.WriteAsync(context,new {error="report_read_timeout",state="unavailable"},503,ct); }
        catch(Exception e) { if(context.Response.HasStarted) throw;await AuthResponse.UnexpectedAsync(context,e,ct,login:false); }
    }
    private static async Task ReadAccountingConnections(HttpContext context, IVpnStore store, VpnAccess access,
        AccessFacts facts, bool definition, CancellationToken ct)
    {
        const string reportKey = "vpn.connections";
        string tab = context.Request.Query["tab"].FirstOrDefault() ?? "employees";
        if (!access.Capabilities.Decide("reports.catalog").Allowed ||
            !access.Capabilities.IsOwner && !access.Capabilities.Capabilities.Contains("vpn.sessions.view"))
            throw new VpnPermissionException("report_access_denied");
        if (!definition && !AccountingTabs.Contains(tab))
            throw new ReportRequestException("module_disabled", 503);

        var registry = context.RequestServices.GetService<IReportDefinitionRegistry>() ?? new ReportDefinitionRegistry();
        var projection = new ReportAccess(registry.Get(reportKey)!, new ReportEligibility().Compose(facts, access.Capabilities));
        await using var db = await store.OpenAccountingAsync(ct);
        if (db is null) throw new ReportRequestException("module_disabled", 503);
        JsonObject payload;
        if (definition)
        {
            payload = projection.Declaration();
            payload["views"] = new JsonArray(payload["views"]!.AsArray().OfType<JsonObject>()
                .Where(view => AccountingTabs.Contains(view.Text("key")))
                .Select(view => (JsonNode)view.DeepClone()).ToArray());
            var domains = await VpnReports.DomainOptions(db, access, ct, accountingOnly: true);
            var (domain, state) = await VpnReports.DefaultDomain(db, access, domains, ct);
            payload["default_domain_id"] = domain;
            payload["default_domain_state"] = state;
            payload["params"] = new JsonArray(payload["params"]!.AsArray().OfType<JsonObject>()
                .Where(parameter => AccountingFilters.Contains(parameter.Text("key")))
                .Select(parameter => (JsonNode)parameter.DeepClone()).ToArray());
            payload["filter_options"] = VpnJson.Obj(new { domain = domains });
            payload["accounting_scope"] = "domain_history";
            var metadata = context.RequestServices.GetRequiredService<IReportV2Metadata>();
            ReportV2Metadata.Annotate(payload, await metadata.PluginAsync(reportKey, ct));
        }
        else
        {
            payload = projection.Project(await VpnReports.Read(db, access, reportKey, context.Request.Query,
                "view", ct, accountingOnly: true));
        }
        await DomainHttp.WriteAsync(context,
            ReportPresentation.Apply(payload, DomainHttp.SelectEnglish(context.Request.Headers.AcceptLanguage.ToString())), 200, ct);
    }
}
