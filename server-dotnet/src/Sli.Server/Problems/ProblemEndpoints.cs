using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;

namespace Sli.Server.Problems;

public static class ProblemEndpoints
{
    public static IServiceCollection AddProblemLifecycle(this IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddScoped<IAccessFactsRepository, AccessFactsRepository>();
        services.TryAddScoped<IProblemRepository, ProblemRepository>();
        return services;
    }
    public static IEndpointRouteBuilder MapProblemLifecycle(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/findings", HandleAsync);
        endpoints.MapGet("/api/findings/risk-responsibles", HandleAsync);
        endpoints.MapGet("/api/findings/{**tail:regex((^|.*/)risk-audit$)}", HandleAsync);
        endpoints.MapGet("/reports/findings.html", Compatibility.LegacyHttpEndpoints.HandleAsync);
        endpoints.MapPost("/api/findings/{**tail:regex((^|.*/)(status|risk-acceptance)$)}", HandleAsync);
        endpoints.MapPost("/api/findings/bulk-status", HandleAsync);
        endpoints.MapGet("/api/v1/watch", HandleAsync);
        endpoints.MapPost("/api/v1/watch", HandleAsync);
        endpoints.MapPost("/api/v1/watch/{**entry}", HandleAsync);
        endpoints.MapGet("/api/v1/decoys", HandleAsync);
        endpoints.MapPost("/api/v1/decoys", HandleAsync);
        endpoints.MapPost("/api/v1/decoys/{**entry}", HandleAsync);
        return endpoints;
    }
    public static async Task HandleAsync(HttpContext context)
    {
        var ct = context.RequestAborted; string path = context.Request.Path.Value ?? "";
        bool watch = path.StartsWith("/api/v1/watch", StringComparison.Ordinal), decoy = path.StartsWith("/api/v1/decoys", StringComparison.Ordinal);
        bool registry = watch || decoy, mutation = HttpMethods.IsPost(context.Request.Method), statusUpdate = path.EndsWith("/status", StringComparison.Ordinal);
        try
        {
            var services = context.RequestServices; var policy = services.GetRequiredService<AuthRequestPolicy>();
            var failure = services.GetRequiredService<TransportGate>().CheckTransport(context);
            if (failure is not null) { await AuthResponse.ErrorAsync(context, failure.Code, failure.StatusCode, ct, login: false); return; }
            if (mutation && !policy.OriginAllowed(context, policy.Resolve(context))) { await AuthResponse.ErrorAsync(context, "cross_origin_request_rejected", 403, ct, login: false); return; }
            Principal principal;
            if (policy.AuthRequired)
            {
                var result = await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context, ct);
                if (!result.Succeeded) { await AuthResponse.ErrorAsync(context, result.Failure?.Code ?? "authentication_required", result.Failure?.StatusCode ?? 401, ct, login: false); return; }
                principal = result.Principal!;
                bool allowed = mutation ? decoy ? principal.Role == "admin" : principal.Role is "operator" or "admin" : TransportGate.CheckViewerRole(principal) is null;
                if (!allowed) { await AuthResponse.ErrorAsync(context, "insufficient_permissions", 403, ct, login: false); return; }
            }
            else
            {
                string expected = (services.GetRequiredService<IConfiguration>()["Sli:OperatorToken"] ?? Environment.GetEnvironmentVariable("ADLOG_OPERATOR_TOKEN") ?? "").Trim();
                if (mutation && expected.Length > 0 && !CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(expected)), SHA256.HashData(Encoding.UTF8.GetBytes(context.Request.Headers["X-ADLog-Operator-Token"].ToString()))))
                { await AuthResponse.ErrorAsync(context, "operator_token_required", 401, ct, login: false); return; }
                principal = new("", 0, "operator");
            }
            var facts = await services.GetRequiredService<IAccessFactsRepository>().LoadAsync(principal, ct);
            var access = new ProblemAccess(new ReportEligibility().Compose(facts, new CapabilityComposer().Compose(facts)));
            string language = context.Request.Headers.AcceptLanguage.ToString(); var query = context.Request.Query;
            var repository = services.GetRequiredService<IProblemRepository>(); JsonObject response;
            // The alias and retired page are resource-aware in the reference.
            if (!registry && path is not ("/api/findings" or "/reports/findings.html"))
            {
                string capability = mutation || path == "/api/findings/risk-responsibles" ? "investigations.manage" : "investigations.view";
                // GET risk-responsibles is also subject to the outer route's
                // investigations.view check before the module's manage check.
                if (!mutation) await RequireCapability(context, access, "investigations.view", ct);
                await RequireCapability(context, access, capability, ct);
            }
            if (registry)
            {
                string report = watch ? "watch.registry" : "decoys.registry";
                access.Registry(report); // denial precedes body and source reads
                if (!mutation)
                {
                    var input = RegistryQuery.Parse(query, watch);
                    response = watch ? await repository.WatchListAsync(input, access, principal, ct) : await repository.DecoyListAsync(input, access, principal, ct);
                }
                else
                {
                    using var body = await AuthJsonBody.ReadAsync(context, ct); var value = JsonNode.Parse(body.RootElement.GetRawText(), documentOptions: new JsonDocumentOptions { MaxDepth = 1000 })!.AsObject();
                    var now = services.GetRequiredService<TimeProvider>().GetUtcNow();
                    string prefix = watch ? "/api/v1/watch" : "/api/v1/decoys";
                    string? rawId = path == prefix ? null : path[(prefix.Length + 1)..];
                    // The reference validates the input before resolving the update ID.
                    if (watch)
                    {
                        var input = WatchInput.Parse(value, now);
                        if (principal.Role is not ("admin" or "operator")) throw new ProblemException("watch_access_denied", 403);
                        response = await repository.WatchSaveAsync(rawId, input, access, principal, CancellationToken.None);
                    }
                    else
                    {
                        var input = DecoyInput.Parse(value); access.Registry(report, input.Identity, true, principal, input.Kind);
                        string? id = rawId is null ? null : ProblemJson.Uuid(rawId, "decoy_invalid");
                        response = await repository.DecoySaveAsync(id, input, access, principal, CancellationToken.None);
                    }
                }
            }
            else if (path == "/reports/findings.html") { context.Response.Redirect(Compatibility.LegacyHttpEndpoints.Redirect(path, query)!); return; }
            else if (path == "/api/findings")
            {
                if (query["source"].Count != 1 || query["source"][0] != "semantic-production") { await DomainHttp.WriteAsync(context, new { error = "legacy_findings_retired" }, 410, ct); return; }
                var input = FindingQuery.Parse(query, access);
                response = await repository.FindingsAsync(input, access, ct);
                response["items"] = new JsonArray(ProblemJson.Array(response["items"]).OfType<JsonObject>().Select(row => (JsonNode)ProblemPresentation.Finding(row, access, language)).ToArray());
            }
            else if (path == "/api/findings/risk-responsibles") response = await repository.ResponsiblesAsync(ct);
            else if (path == "/api/findings/bulk-status")
            {
                using var body = await AuthJsonBody.ReadAsync(context, ct);
                var value = JsonNode.Parse(body.RootElement.GetRawText()) as JsonObject;
                if (value?.Count != 2 || value["ids"] is not JsonArray ids || ids.Count is < 1 or > 200 ||
                    ProblemJson.Text(value["status"]) is not ("closed" or "active"))
                    throw new ProblemException("invalid_bulk_status");
                var selection = ids.Select(id => ProblemJson.Id(id, "invalid_finding_id", ProblemJson.SafeInteger)).Distinct().Order().ToArray();
                string actor = ProblemJson.Actor(principal, false);
                var decision = new JsonObject { ["status"] = value["status"]!.DeepClone() };
                if (ProblemJson.Text(decision["status"]) == "active") decision["status_reason"] = "Reopened from the Problems queue";
                response = await repository.BulkStatusAsync(selection, FindingStatusInput.Parse(decision, actor), actor, access, CancellationToken.None);
            }
            else
            {
                string raw = context.Features.Get<IHttpRequestFeature>()?.RawTarget is { Length: > 0 } target ? target.Split('?', 2)[0] : path;
                string[] parts = raw.Split('/', StringSplitOptions.RemoveEmptyEntries);
                bool audit = path.EndsWith("/risk-audit", StringComparison.Ordinal);
                string invalid = audit ? "invalid_cursor_or_finding" : "invalid_finding_id";
                if (parts.Length != 4 || !long.TryParse(parts[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out long id) || !statusUpdate && id <= 0) throw new ProblemException(invalid);
                if (audit)
                {
                    long? before = null;
                    if (query.TryGetValue("before", out var value)) { if (!long.TryParse(value.FirstOrDefault(), out long number) || number <= 0) throw new ProblemException(invalid); before = number; }
                    response = await repository.RiskAuditAsync(id, before, ct);
                }
                else
                {
                    using var body = await AuthJsonBody.ReadAsync(context, ct); var value = JsonNode.Parse(body.RootElement.GetRawText(), documentOptions: new JsonDocumentOptions { MaxDepth = 1000 })!.AsObject();
                    string actor = ProblemJson.Actor(principal, !statusUpdate);
                    response = statusUpdate ? await repository.StatusAsync(id, FindingStatusInput.Parse(value, actor), actor, CancellationToken.None) :
                        await repository.RiskAsync(id, RiskInput.Parse(value, actor, services.GetRequiredService<TimeProvider>().GetUtcNow()), CancellationToken.None);
                }
            }
            await DomainHttp.WriteAsync(context, response, 200, ct);
        }
        catch (CapabilityDenied) { }
        catch (ProblemException error)
        {
            if (registry) await RegistryError(context, watch, error.Code, error.Status, ct);
            else if (statusUpdate) await DomainHttp.WriteAsync(context, new { error = error.Code, message = error.Message }, error.Status, ct);
            else await DomainHttp.WriteAsync(context, new { error = error.Code }, error.Status, ct);
        }
        catch (AuthInputException error)
        {
            // Registry modules catch the source RequestInputError(ValueError).
            if (registry) await RegistryError(context, watch, watch ? "watch_invalid" : "decoy_invalid", 400, ct);
            else await AuthResponse.ErrorAsync(context, error.Code, error.StatusCode, ct, login: false);
        }
        catch (PostgresException error) when (registry)
        { await RegistryError(context, watch, error.SqlState == "23505" ? watch ? "watch_revision_conflict" : "decoy_duplicate" : watch ? "watch_unavailable" : "decoy_unavailable", error.SqlState == "23505" ? 409 : 503, ct); }
        catch (InvalidOperationException error) when (error.Message == "storage_v2_admission_required")
        { await DomainHttp.WriteAsync(context, new { error = "storage_transition_authorization_invalid" }, 503, ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception error)
        {
            if (context.Response.HasStarted) throw;
            if (registry) await RegistryError(context, watch, watch ? "watch_unavailable" : "decoy_unavailable", 503, ct);
            else await AuthResponse.UnexpectedAsync(context, error, ct, login: false);
        }
    }
    private sealed class CapabilityDenied : Exception;
    private static async Task RequireCapability(HttpContext context, ProblemAccess access, string key, CancellationToken ct)
    {
        var result = access.Decision.Capabilities.Decide(key);
        if (result.Allowed) return;
        await DomainHttp.WriteAsync(context, new { error = result.Reason, required_capability = key }, 403, ct); throw new CapabilityDenied();
    }
    private static Task RegistryError(HttpContext context, bool watch, string code, int status, CancellationToken ct)
    {
        string prefix = watch ? "watch" : "decoy";
        if (status == 403) code = prefix + "_access_denied";
        string key = (watch ? "watch" : "decoys") + (status == 403 ? ".denied" : status == 409 ? ".conflict" : ".failed");
        if (code.StartsWith("report_", StringComparison.Ordinal)) code = prefix + "_access_denied";
        return DomainHttp.WriteAsync(context, new { error = code, message = ProblemPresentation.Message(key, context.Request.Headers.AcceptLanguage.ToString()) }, status, ct);
    }
}
