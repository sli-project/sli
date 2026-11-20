using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;

namespace Sli.Server.Operations;

public sealed class OperationsInputException(string code, int status = 400) : Exception(code)
{
    public int Status { get; } = status;
}

public static class OperationsEndpoints
{
    public static readonly string[] GetRoutes = [
        "/api/v1/operations/overview", "/api/v1/operations/sources/{hostname}",
        "/api/v1/operations/administrative-activity", "/api/v1/source-packs", "/api/v1/source-adapters",
        "/api/db/status", "/api/diagnostics/overview", "/api/storage/health", "/api/storage/lifecycle",
        "/api/system/health", "/api/health/details", "/api/runtime/status", "/api/sources",
        "/api/domain-controllers", "/api/collector/health", "/api/jobs", "/api/jobs/{id}",
        "/api/logs/tail", "/api/autocollection/status"
    ];

    public static IServiceCollection AddOperations(this IServiceCollection services)
    {
        services.TryAddScoped<IAccessFactsRepository, AccessFactsRepository>();
        services.TryAddScoped<IOperationsQueries, OperationsQueries>();
        services.TryAddSingleton<OperationsFiles>();
        services.TryAddSingleton<OperationsCatalog>();
        services.TryAddSingleton<OperationsJobs>();
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddScoped<OperationsService>();
        return services;
    }

    public static IEndpointRouteBuilder MapOperations(this IEndpointRouteBuilder endpoints)
    {
        foreach (string route in GetRoutes) endpoints.MapGet(route, HandleAsync);
        endpoints.MapPost("/api/v1/source-onboarding/preflight", HandleAsync);
        return endpoints;
    }

    public static async Task HandleAsync(HttpContext context)
    {
        var ct = context.RequestAborted;
        try
        {
            var services = context.RequestServices;
            var transport = services.GetRequiredService<TransportGate>().CheckTransport(context);
            if (transport is not null) { await DomainHttp.WriteFailureAsync(context, transport, ct); return; }
            var policy = services.GetRequiredService<AuthRequestPolicy>();
            bool preflight = HttpMethods.IsPost(context.Request.Method);
            if (preflight && !policy.OriginAllowed(context, policy.Resolve(context)))
            { await Error(context, "cross_origin_request_rejected", 403); return; }
            Principal principal;
            if (policy.AuthRequired)
            {
                var auth = await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context, ct);
                if (!auth.Succeeded) { await DomainHttp.WriteFailureAsync(context, auth.Failure ?? new(401, "authentication_required"), ct); return; }
                principal = auth.Principal!;
                if (TransportGate.CheckViewerRole(principal) is {} failure) { await DomainHttp.WriteFailureAsync(context, failure, ct); return; }
                if (preflight && principal.Role is not ("operator" or "admin"))
                { await Error(context, "insufficient_permissions", 403); return; }
            }
            else
            {
                if (preflight)
                {
                    string expected = services.GetRequiredService<IConfiguration>()["Sli:OperatorToken"] ?? Environment.GetEnvironmentVariable("ADLOG_OPERATOR_TOKEN") ?? "";
                    if (expected.Trim().Length > 0 && !CryptographicOperations.FixedTimeEquals(
                        SHA256.HashData(Encoding.UTF8.GetBytes(expected.Trim())), SHA256.HashData(Encoding.UTF8.GetBytes(context.Request.Headers["X-ADLog-Operator-Token"].ToString()))))
                    { await Error(context, "operator_token_required", 401); return; }
                }
                principal = new("", 0, "operator");
            }
            var facts = await services.GetRequiredService<IAccessFactsRepository>().LoadAsync(principal, ct);
            var caps = new CapabilityComposer().Compose(facts);
            string path = context.Request.Path.Value ?? "";
            bool journal = path == "/api/v1/operations/administrative-activity";
            string capability = journal ? "administrative.activity.view" : "operations.view";
            var decision = caps.Decide(capability);
            if (!decision.Allowed)
            {
                await DomainHttp.WriteAsync(context, new { error = decision.Reason, required_capability = capability }, 403, ct); return;
            }
            // The source has a second role gate, after the mutation/capability gates.
            if (preflight && policy.AuthRequired && principal.Role != "admin")
            { await Error(context, "insufficient_permissions", 403); return; }
            var service = services.GetRequiredService<OperationsService>();
            var query = Query(context);
            JsonNode? output;
            if (preflight)
            {
                using var body = await AuthJsonBody.ReadAsync(context, ct);
                output = await service.PreflightAsync(JsonNode.Parse(body.RootElement.GetRawText())!.AsObject(), ct);
            }
            else if (path.StartsWith("/api/v1/operations/sources/", StringComparison.Ordinal))
                output = await service.SourceAsync(context.Request.RouteValues["hostname"]?.ToString() ?? "", ct);
            else if (path.StartsWith("/api/jobs/", StringComparison.Ordinal))
            {
                if (!long.TryParse(context.Request.RouteValues["id"]?.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out long id))
                    throw new OperationsInputException("invalid_job_id");
                output = service.Job(id) ?? throw new OperationsInputException("job_not_found", 404);
            }
            else output = await service.ReadAsync(path, query, ct);
            await DomainHttp.WriteAsync(context, output!, 200, ct);
        }
        catch (OperationsInputException error) { await Error(context, error.Message, error.Status); }
        catch (AuthInputException error) { await Error(context, error.Code, error.StatusCode); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception error) { if (context.Response.HasStarted) throw; await AuthResponse.UnexpectedAsync(context, error, ct, login: false); }
    }

    internal static Dictionary<string, string[]> Query(HttpContext context) => context.Request.Query
        .Select(pair => (pair.Key, Values: pair.Value.Where(v => !string.IsNullOrEmpty(v)).Select(v => v!).ToArray()))
        .Where(pair => pair.Values.Length > 0).ToDictionary(pair => pair.Key, pair => pair.Values, StringComparer.Ordinal);
    internal static string First(Dictionary<string, string[]> query, string key, string fallback) => query.TryGetValue(key, out var values) ? values[0] : fallback;
    internal static bool Flag(Dictionary<string, string[]> query, string key, string fallback = "0") => First(query, key, fallback).ToLowerInvariant() is "1" or "true" or "yes";
    internal static Task Error(HttpContext context, string code, int status) => DomainHttp.WriteAsync(context, new { error = code }, status, context.RequestAborted);
}
