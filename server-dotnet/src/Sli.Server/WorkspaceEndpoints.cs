using System.Text.Json;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Auth;
using Sli.Server.Domains;
using Sli.Server.Infrastructure;
using Sli.Server.Notifications;

namespace Sli.Server.Workspace;

public static class WorkspaceEndpoints
{
    public static IEndpointRouteBuilder MapWorkspaceEndpoints(this IEndpointRouteBuilder endpoints)
    {
        foreach (string route in new[] { "/api/v1/ui/bootstrap", "/api/v1/overview", "/api/v2/reports" })
            endpoints.MapGet(route, async (HttpContext context, AccessReadService service, IPrincipalAuthenticator auth,
                TransportGate transport, IWorkspaceRows rows, IReportCatalogProvider catalog, ILogger<AccessReadService> logger) =>
            {
                var ct = context.RequestAborted;
                try
                {
                    var failure = transport.CheckTransport(context);
                    if (failure is not null) { await DomainHttp.WriteFailureAsync(context, failure, ct); return; }
                    var authenticated = await auth.AuthenticateAsync(context, ct);
                    if (!authenticated.Succeeded) { await DomainHttp.WriteFailureAsync(context, authenticated.Failure ?? new(401, "authentication_required"), ct); return; }
                    var principal = authenticated.Principal!;
                    failure = TransportGate.CheckViewerRole(principal);
                    if (failure is not null) { await DomainHttp.WriteFailureAsync(context, failure, ct); return; }
                    var access = await service.LoadAsync(principal, ct);
                    string capability = route == "/api/v2/reports" ? "reports.catalog" : "workspace.view";
                    var decision = access.Capabilities.Decide(capability);
                    if (!decision.Allowed)
                    {
                        await DomainHttp.WriteAsync(context, new { error = decision.Reason, required_capability = capability }, 403, ct);
                        return;
                    }
                    if (route == "/api/v1/ui/bootstrap")
                    {
                        string language = context.Request.Headers.AcceptLanguage.ToString();
                        // The interface sends its selected locale explicitly on bootstrap after reloading.
                        if (principal.Type == "session" && principal.Id > 0 && language is "en" or "ru" &&
                            context.RequestServices.GetService<IPostgresConnectionFactory>() is {} database)
                            await NotificationLanguages.RememberInterfaceAsync(database, principal.Id, language, ct);
                        await DomainHttp.WriteAsync(context, Bootstrap(principal, access), 200, ct);
                        return;
                    }
                    if (route == "/api/v1/overview")
                    {
                        if (context.Request.Query["view"].Count == 1 && context.Request.Query["view"][0] == "agents")
                        {
                            var health = await new AgentCollectionOverview(rows).ReadAsync(ct);
                            await DomainHttp.WriteAsync(context, new { api_version = "v1", agent_collection = health }, 200, ct);
                        }
                        else await DomainHttp.WriteAsync(context, await new WorkspaceOverview(rows, context.RequestServices.GetRequiredService<DashboardSnapshotReader>(), context.RequestServices.GetService<IConfiguration>()).ReadAsync(context.Request.Query, ct), 200, ct);
                        return;
                    }
                    await DomainHttp.WriteAsync(context, await new WorkspaceReportCatalog(rows, catalog,
                        context.RequestServices.GetService<IConfiguration>()).ReadAsync(access, ct), 200, ct);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
                catch (Exception ex) { if (context.Response.HasStarted) throw; await DomainHttp.WriteUnexpectedAsync(context, logger, ex, ct, route); }
            });
        return endpoints;
    }

    public static object Bootstrap(Principal principal, AccessReadEvaluation access)
    {
        var projection = JsonSerializer.SerializeToElement(AccessReadProjection.Compose(principal, access.Facts, access.Capabilities, access.Reports, false));
        var identity = new Dictionary<string, object?> { ["type"] = principal.Type, ["id"] = principal.Id, ["role"] = principal.Role };
        if (principal.Username is not null) identity["username"] = principal.Username;
        if (principal.Label is not null) identity["label"] = principal.Label;
        return new { principal = identity, effective_role = principal.Role,
            api_time_contract = "UTC ISO-8601; browser renders the selected local timezone",
            navigation = projection.GetProperty("navigation"), access_model = "composite_v4",
            capabilities = projection.GetProperty("capabilities"), packages = projection.GetProperty("packages"),
            allowed_report_count = projection.GetProperty("allowed_report_count") };
    }

    public static object EmptyAgents(DateTimeOffset now) => new { api_version = "v1", agent_collection = AgentCollectionOverview.Compose([], [], now) };
}
