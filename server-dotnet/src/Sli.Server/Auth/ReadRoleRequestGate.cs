using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;

namespace Sli.Server.Auth;

public sealed record BrowserReadRoleResponse;

public static class ReadRoleRequestGate
{
    // Frozen Python http_server.py IT_ONLY_PATHS / _required_read_role (ddce909d).
    private static readonly HashSet<string> OperatorPaths = new(StringComparer.OrdinalIgnoreCase)
    {
        "/api/runtime/status", "/api/sources", "/api/domain-controllers", "/api/collector/health",
        "/api/system/health", "/api/storage/health", "/api/storage/lifecycle", "/api/db/status",
        "/api/diagnostics/overview",
        "/api/jobs", "/api/autocollection/status", "/api/logs/tail", "/reports/collector-health.html",
        "/reports/autocollection.html", "/reports/storage-health.html", "/reports/system-health.html",
        "/reports/db-status.html", "/reports/diagnostics.html",
        "/api/v1/operations/overview", "/api/v1/operations/plugins",
        "/api/v1/operations/administrative-activity", "/api/v1/source-packs", "/api/v1/source-adapters"
    };

    internal static string RequiredRole(string path)
    {
        // ASP.NET route matching accepts case variants and a trailing slash.
        // They must not bypass the role required by the canonical route.
        path = path.TrimEnd('/');
        if (path.Equals("/admin", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("/api/auth/users", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("/api/auth/api-keys", StringComparison.OrdinalIgnoreCase)) return "admin";
        return OperatorPaths.Contains(path) || path.StartsWith("/api/jobs/", StringComparison.OrdinalIgnoreCase)
            ? "operator" : "viewer";
    }

    public static IApplicationBuilder UseReadRoleRequestGate(this IApplicationBuilder app) => app.Use(async (context, next) =>
    {
        // Mutation handlers retain their independent origin, token and role gates.
        if (!HttpMethods.IsGet(context.Request.Method) && !HttpMethods.IsHead(context.Request.Method))
        { await next(context); return; }
        string required = RequiredRole(context.Request.Path.Value ?? "");
        if (required == "viewer" || !context.RequestServices.GetRequiredService<AuthRequestPolicy>().AuthRequired)
        { await next(context); return; }

        var ct = context.RequestAborted;
        var services = context.RequestServices;
        var failure = services.GetRequiredService<TransportGate>().CheckTransport(context);
        if (failure is not null) { await DomainHttp.WriteFailureAsync(context, failure, ct); return; }
        var auth = await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context, ct);
        bool browser = context.GetEndpoint()?.Metadata.GetMetadata<BrowserReadRoleResponse>() is not null;
        if (!auth.Succeeded)
        {
            if (browser) context.Response.Redirect("/login" + QueryString.Create("next", context.Request.Path + context.Request.QueryString));
            else await DomainHttp.WriteFailureAsync(context, auth.Failure ?? new(401, "authentication_required"), ct);
            return;
        }
        if (auth.Principal!.Role != "admin" && (required == "admin" || auth.Principal.Role != "operator"))
        {
            if (browser) context.Response.Redirect("/");
            else await DomainHttp.WriteAsync(context, new { error = "insufficient_permissions" }, 403, ct);
            return;
        }
        // Capabilities and any stronger endpoint-specific checks run only after the role.
        await next(context);
    });
}
