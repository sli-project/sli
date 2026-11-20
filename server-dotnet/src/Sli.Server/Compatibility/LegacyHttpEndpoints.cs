using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;
using Sli.Server.Operations;
using System.Security.Cryptography;
using System.Text;
using Sli.Server.Storage.EventReports;

namespace Sli.Server.Compatibility;

public static class LegacyHttpEndpoints
{
    public static IServiceCollection AddLegacyHttp(this IServiceCollection services)
    {
        services.TryAddScoped<IAccessFactsRepository, AccessFactsRepository>();
        services.TryAddScoped<ILegacyRows, PostgresLegacyRows>();
        services.TryAddScoped<ILegacyHttpReader, LegacyHttpReader>();
        services.TryAddScoped<IOperationsQueries, OperationsQueries>();
        services.TryAddSingleton<OperationsFiles>();
        services.TryAddScoped<DbStatusReport>();
        services.TryAddScoped<AiRunRepository>();
        return services;
    }

    public static IEndpointRouteBuilder MapLegacyHttp(this IEndpointRouteBuilder endpoints)
    {
        foreach (string route in new[] {
            "/api/events/details", "/api/events/search", "/api/events/search/deep", "/api/events/summary", "/api/events/timeline",
            "/api/entities/details", "/api/entities/summary", "/api/ai/prompt-preview", "/api/ai/redaction-preview", "/api/ai/runs",
            "/api/security/events-monitor", "/reports/security-events-monitor.csv", "/reports/domain-security-overview.html",
            "/reports/ai-analysis.html", "/reports/ai-prompt-preview.html", "/reports/ai-redaction-preview.html", "/reports/ai-reports.html",
            "/reports/search.html", "/reports/search-deep.html", "/reports/event-details.html", "/reports/entity-details.html",
            "/reports/account-timeline.html", "/reports/security-events-monitor.html",
            "/reports/collector-health.html", "/reports/autocollection.html", "/reports/db-status.html",
            "/reports/diagnostics.html", "/reports/storage-health.html", "/reports/system-health.html",
            "/reports/investigation.html", "/reports/role-overview.html", "/reports/ui-navigation.html" })
        {
            var mapped = endpoints.MapGet(route, HandleAsync);
            if (route.EndsWith(".html", StringComparison.Ordinal)) mapped.WithMetadata(new BrowserReadRoleResponse());
        }
        // More specific routes win over both the SPA catch-all and this artifact guard.
        endpoints.MapGet("/reports/{**artifact}", HandleAsync);
        return endpoints;
    }

    public static async Task HandleAsync(HttpContext context)
    {
        var ct = context.RequestAborted;
        string path = context.Request.Path.Value ?? "";
        // ASP.NET accepts case variants and one trailing slash for this route.
        string reportPath = path.EndsWith('/') ? path[..^1] : path;
        if (reportPath.Equals("/reports/db-status.html", StringComparison.OrdinalIgnoreCase)) path = "/reports/db-status.html";
        bool api = path.StartsWith("/api/", StringComparison.Ordinal);
        try
        {
            var services = context.RequestServices;
            if (services.GetRequiredService<TransportGate>().CheckTransport(context) is {} transport)
            { await DomainHttp.WriteFailureAsync(context, transport, ct); return; }
            Principal principal;
            if (services.GetRequiredService<AuthRequestPolicy>().AuthRequired)
            {
                var authentication = await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context, ct);
                if (!authentication.Succeeded)
                {
                    if (api) await DomainHttp.WriteFailureAsync(context, authentication.Failure ?? new(401, "authentication_required"), ct);
                    else context.Response.Redirect("/login" + QueryString.Create("next", context.Request.Path + context.Request.QueryString));
                    return;
                }
                principal = authentication.Principal!;
                if (TransportGate.CheckViewerRole(principal) is {} role)
                {
                    if (api) await DomainHttp.WriteFailureAsync(context, role, ct);
                    else context.Response.Redirect("/");
                    return;
                }
                // The Python dispatcher requires operator before the capability check and React redirect.
                if (path == "/reports/system-health.html" && principal.Role is not ("operator" or "admin"))
                {
                    context.Response.Redirect("/");
                    return;
                }
            }
            else principal = new("", 0, "operator");
            string? capability = Capability(path);
            if (capability is not null)
            {
                var facts = await services.GetRequiredService<IAccessFactsRepository>().LoadAsync(principal, ct);
                var decision = new CapabilityComposer().Compose(facts).Decide(capability);
                if (!decision.Allowed)
                {
                    await DomainHttp.WriteAsync(context, new { error = decision.Reason, required_capability = capability }, 403, ct);
                    return;
                }
            }
            if (path == "/reports/db-status.html")
            {
                var data = await services.GetRequiredService<DbStatusReport>().ReadAsync(ct);
                string nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
                string html = DbStatusReport.Render(data).Replace("<style>", "<style nonce=\"" + nonce + "\">", StringComparison.Ordinal);
                byte[] bytes = Encoding.UTF8.GetBytes(html);
                context.Response.ContentType = "text/html; charset=utf-8";
                context.Response.ContentLength = bytes.Length;
                DomainHttp.ApplyHeaders(context, nonce: nonce);
                await context.Response.Body.WriteAsync(bytes, ct);
                return;
            }
            string? target = Redirect(path, context.Request.Query);
            if (target is not null) { context.Response.Redirect(target); return; }
            if (path.StartsWith("/reports/", StringComparison.Ordinal) && path is not
                ("/reports/security-events-monitor.csv" or "/reports/ai-analysis.html" or "/reports/ai-reports.html" or
                 "/reports/ai-redaction-preview.html" or "/reports/ai-prompt-preview.html"))
            {
                await DomainHttp.WriteAsync(context, new { error = "report_artifact_unclassified" }, 403, ct);
                return;
            }
            var query = LegacyQuery.Parse(path, context.Request.Query);
            var result = await services.GetRequiredService<ILegacyHttpReader>().ReadAsync(path, query, ct);
            if (path.EndsWith(".csv", StringComparison.Ordinal))
                await LegacyRender.CsvAsync(context, result, ct);
            else if (path.EndsWith(".html", StringComparison.Ordinal))
                await LegacyRender.HtmlAsync(context, path, result, ct);
            else await DomainHttp.WriteAsync(context, result, 200, ct);
        }
        catch (LegacyInputException error)
        { await DomainHttp.WriteAsync(context, new { error = error.Message }, error.Status, ct); }
        catch (Exception error) when (error is TimeoutException or PostgresException { SqlState: "57014" }
            or NpgsqlException { InnerException: TimeoutException })
        { await DomainHttp.WriteAsync(context, new { error = "report_read_timeout", state = "unavailable" }, 503, ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (EventReadConfigurationException error)
        { await DomainHttp.WriteAsync(context, new { error = error.Message, state = "unavailable" }, 503, ct); }
        catch (Exception error)
        { if (context.Response.HasStarted) throw; await AuthResponse.UnexpectedAsync(context, error, ct, login: false); }
        finally
        {
            // Match http_access without putting query values or identities in logs.
            context.RequestServices.GetService<ILoggerFactory>()?.CreateLogger("Sli.Server.Compatibility")
                .LogInformation("http_access method={Method} route={Route} status={Status}", context.Request.Method, path, context.Response.StatusCode);
        }
    }

    internal static string? Capability(string path) => path switch
    {
        "/reports/collector-health.html" or "/reports/autocollection.html" or "/reports/db-status.html" or
        "/reports/diagnostics.html" or "/reports/storage-health.html" or "/reports/system-health.html" => "operations.view",
        "/reports/investigation.html" => "investigations.view",
        "/reports/role-overview.html" or "/reports/ui-navigation.html" => "workspace.view",
        "/api/events/details" or "/reports/event-details.html" => "evidence.exact",
        _ when path.StartsWith("/api/ai/") || path.StartsWith("/reports/ai-") => "semantic.review",
        _ when path.StartsWith("/api/entities/") || path == "/reports/entity-details.html" => "objects.view",
        _ when path.StartsWith("/api/events/") || path.StartsWith("/api/security/events-monitor") ||
            path.StartsWith("/reports/security-events-monitor") || path.StartsWith("/reports/search") || path == "/reports/account-timeline.html" => "events.view",
        _ => null
    };

    internal static string? Redirect(string path, IQueryCollection query)
    {
        if (path is "/reports/event-details.html" or "/reports/entity-details.html")
        {
            bool entity = path == "/reports/entity-details.html";
            string? raw = LegacyQuery.First(query, entity ? "entity_id" : "event_db_id", entity ? "entity_id" : "id");
            string target = entity ? "/app/entities" : "/app/events";
            return System.Numerics.BigInteger.TryParse(raw, out var id) && id > 0 ? target + "/" + id.ToString(System.Globalization.CultureInfo.InvariantCulture) : target;
        }
        string? destination = path switch
        {
            "/reports/findings.html" => "/app/scenarios",
            "/reports/search.html" or "/reports/search-deep.html" or "/reports/security-events-monitor.html" => "/app/events",
            "/reports/account-timeline.html" or "/reports/investigation.html" => "/app/investigations",
            "/reports/collector-health.html" or "/reports/autocollection.html" or
            "/reports/diagnostics.html" or "/reports/storage-health.html" or "/reports/system-health.html" => "/app/operations",
            "/reports/role-overview.html" or "/reports/ui-navigation.html" => "/app/settings",
            _ => null
        };
        if (destination is null) return null;
        string[] preserved = ["q", "scope", "event_db_id", "entity_id", "event_id", "server", "channel", "time_from", "time_to", "risk", "status", "result_class", "risk_class"];
        var values = query.Where(pair => preserved.Contains(pair.Key)).Select(pair => (pair.Key, Value: LegacyQuery.First(query, pair.Key)))
            .Where(pair => !string.IsNullOrWhiteSpace(pair.Value));
        return destination + QueryString.Create(values.Select(pair => new KeyValuePair<string, string?>(pair.Key, pair.Value))).ToString().Replace("%20","+");
    }
}
