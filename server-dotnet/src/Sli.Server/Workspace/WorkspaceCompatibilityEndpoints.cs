using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;

namespace Sli.Server.Workspace;

public interface IWorkspaceCompatibilityReader
{
    Task<JsonObject> ReadAsync(string path, IQueryCollection query, Principal principal, AccessReadEvaluation access, CancellationToken ct);
}
public static class WorkspaceCompatibilityEndpoints
{
    public static readonly string[] Routes = ["/api/dashboard/snapshot", "/api/investigation/workspace", "/api/role-views", "/api/ui/navigation", "/api/v1/ui/route-parity", "/api/v1/workspace"];
    public static IServiceCollection AddWorkspaceCompatibility(this IServiceCollection services) {
        services.TryAddScoped<IWorkspaceCompatibilityReader, WorkspaceCompatibilityReader>();
        services.TryAddScoped<DashboardSnapshotReader>(); services.TryAddScoped<LegacyInvestigationReader>();
        services.TryAddSingleton<DashboardSnapshotCache>();
        services.AddHostedService<DashboardWarmupService>(); return services;
    }
    public static IEndpointRouteBuilder MapWorkspaceCompatibility(this IEndpointRouteBuilder endpoints) {
        foreach (string route in Routes) endpoints.MapGet(route, HandleAsync); return endpoints;
    }
    public static async Task HandleAsync(HttpContext context) {
        var ct = context.RequestAborted;
        try {
            var services = context.RequestServices;
            if (services.GetRequiredService<TransportGate>().CheckTransport(context) is {} transport) { await WriteFailureAsync(context, transport, ct); return; }
            Principal principal;
            if (services.GetRequiredService<AuthRequestPolicy>().AuthRequired) {
                var auth = await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context, ct);
                if (!auth.Succeeded) { await WriteFailureAsync(context, auth.Failure ?? new(401, "authentication_required"), ct); return; }
                principal = auth.Principal!;
                if (TransportGate.CheckViewerRole(principal) is {} role) { await WriteFailureAsync(context, role, ct); return; }
            } else principal = new("", 0, "operator");
            var facts = await services.GetRequiredService<IAccessFactsRepository>().LoadAsync(principal, ct);
            var capabilities = new CapabilityComposer().Compose(facts);
            string capability = context.Request.Path == "/api/investigation/workspace" ? "investigations.view" : "workspace.view";
            var decision = capabilities.Decide(capability);
            if (!decision.Allowed) { await DomainHttp.WriteAsync(context, new { error = decision.Reason, required_capability = capability }, 403, ct); return; }
            var access = new AccessReadEvaluation(facts, capabilities, new ReportEligibility().Compose(facts, capabilities));
            var result = await services.GetRequiredService<IWorkspaceCompatibilityReader>().ReadAsync(context.Request.Path.Value!, context.Request.Query, principal, access, ct);
            await DomainHttp.WriteAsync(context, result, 200, ct);
        }
        catch (Compatibility.LegacyInputException e) { await DomainHttp.WriteAsync(context, new { error = e.Message }, e.Status, ct); }
        catch (Reporting.ReportException e) { await DomainHttp.WriteAsync(context, new { error = e.Message }, e.Status, ct); }
        catch (Npgsql.PostgresException e) when (context.Request.Path == "/api/investigation/workspace" && e.SqlState == "57014")
        { await DomainHttp.WriteAsync(context, new { error = "report_read_timeout", state = "unavailable" }, 503, ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception e) { if (context.Response.HasStarted) throw; await AuthResponse.UnexpectedAsync(context, e, ct, login: false); }
    }
    private static Task WriteFailureAsync(HttpContext context, AuthenticationFailure failure, CancellationToken ct) =>
        context.Request.Path == "/api/role-views"
            ? DomainHttp.WriteAsync(context, new { error = failure.Code }, failure.StatusCode, ct)
            : DomainHttp.WriteFailureAsync(context, failure, ct);
}

internal static partial class LegacyWorkspaceModels
{
    internal static JsonObject Navigation(IConfiguration configuration) {
        var source = JsonNode.Parse(WorkspaceJson.ReadResource("legacy-navigation.json"))!;
        var items = source["NAV_ITEMS"]!.AsArray();
        foreach (var item in items) item!["role_titles"] = new JsonArray(item["roles"]!.AsArray().Select(r => source["ROLE_TITLES"]![r!.ToString()]!.DeepClone()).ToArray());
        var roles = new JsonArray();
        foreach (var id in source["ROLE_ORDER"]!.AsArray()) roles.Add(new JsonObject { ["id"] = id!.DeepClone(), ["title"] = source["ROLE_TITLES"]![id.ToString()]!.DeepClone(), ["items"] = new JsonArray(items.Where(i => i!["roles"]!.AsArray().Any(r => r!.ToString() == id.ToString())).Select(i => i!.DeepClone()).ToArray()) });
        var groups = new JsonArray();
        foreach (var (id, title) in source["GROUP_TITLES"]!.AsObject()) groups.Add(new JsonObject { ["id"] = id, ["title"] = title!.DeepClone(), ["items"] = new JsonArray(items.Where(i => i!["group"]!.ToString() == id).Select(i => i!.DeepClone()).ToArray()) });
        return new() { ["package_type"] = "UI_NAVIGATION", ["status"] = "ok", ["generated_at_utc"] = DateTimeOffset.UtcNow,
            ["release_metadata"] = Hosting.ReleaseMetadata.Public(configuration),
            ["roles"] = roles, ["groups"] = groups, ["items"] = items.DeepClone(), ["principle"] = "Ролевой вид меняет акценты интерфейса, но не скрывает доказательства и технические отчеты окончательно." };
    }
    internal static JsonObject Parity() {
        var source = JsonNode.Parse(WorkspaceJson.ReadResource("route-parity.json"))!;
        var mapped = new JsonArray();
        void Add(string path, string target) => mapped.Add(new JsonObject { ["legacy_path"] = path, ["react_path"] = target, ["state"] = "redirected", ["fallback"] = null });
        foreach (var (path, target) in source["direct"]!.AsObject().OrderBy(p => p.Key, StringComparer.Ordinal)) Add(path, target!.ToString());
        Add("/admin", "/app/admin"); Add("/reports/event-details.html", "/app/events/{event_db_id}"); Add("/reports/entity-details.html", "/app/entities/{entity_id}");
        return new() { ["status"] = "accepted", ["ui_platform"] = "react", ["legacy_default"] = "redirect", ["legacy_fallback"] = "removed", ["mapped_routes"] = mapped, ["export_only_routes"] = source["export_only_routes"]!.DeepClone(), ["csv_exports_redirected"] = false };
    }
}
