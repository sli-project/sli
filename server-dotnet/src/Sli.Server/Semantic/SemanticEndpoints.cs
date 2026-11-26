using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;
using Npgsql;

namespace Sli.Server.Semantic;

public static class SemanticEndpoints
{
    public static IServiceCollection AddSemantic(this IServiceCollection services)
    {
        services.TryAddScoped<IAccessFactsRepository, AccessFactsRepository>();
        services.TryAddScoped<ISemanticDatabase, SemanticDatabase>();
        services.TryAddScoped<SemanticWorkspace>(); services.TryAddScoped<SemanticGovernance>();
        services.TryAddScoped<SemanticRelations>(); services.TryAddScoped<SigmaProjection>();
        return services;
    }
    public static IEndpointRouteBuilder MapSemantic(this IEndpointRouteBuilder endpoints)
    {
        foreach (string leaf in new[] { "scenarios", "actions", "calibration", "relations", "sigma-rules", "attack-coverage" })
            endpoints.MapGet("/api/v1/semantic/" + leaf, HandleAsync);
        endpoints.MapGet("/api/v1/semantic/sigma-live-rules", HandleAsync);
        endpoints.MapPost("/api/v1/semantic/sigma-live-rules", HandleAsync);
        endpoints.MapPost("/api/v1/semantic/scenarios/{id}/review", HandleAsync);
        endpoints.MapGet("/api/v1/platform-settings/semantic-control", HandleAsync);
        endpoints.MapPost("/api/v1/platform-settings/semantic-control", HandleAsync);
        return endpoints;
    }
    public static async Task HandleAsync(HttpContext context)
    {
        var ct = context.RequestAborted;
        try
        {
            var services = context.RequestServices;
            if (services.GetRequiredService<TransportGate>().CheckTransport(context) is { } failure)
            { await DomainHttp.WriteFailureAsync(context, failure, ct); return; }
            var policy = services.GetRequiredService<AuthRequestPolicy>();
            bool mutation = HttpMethods.IsPost(context.Request.Method);
            if (mutation && !policy.OriginAllowed(context, policy.Resolve(context)))
            { await Error(context, "cross_origin_request_rejected", 403); return; }
            Principal principal;
            if (policy.AuthRequired)
            {
                var authentication = await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context, ct);
                if (!authentication.Succeeded)
                { await DomainHttp.WriteFailureAsync(context, authentication.Failure ?? new(401, "authentication_required"), ct); return; }
                principal = authentication.Principal!;
                if (TransportGate.CheckViewerRole(principal) is { } role)
                { await DomainHttp.WriteFailureAsync(context, role, ct); return; }
            }
            else
            {
                string expected = services.GetRequiredService<IConfiguration>()["Sli:OperatorToken"] ?? Environment.GetEnvironmentVariable("ADLOG_OPERATOR_TOKEN") ?? "";
                if (mutation && expected.Trim().Length > 0 && !CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(expected.Trim())),
                    SHA256.HashData(Encoding.UTF8.GetBytes(context.Request.Headers["X-ADLog-Operator-Token"].ToString()))))
                { await Error(context, "operator_token_required", 401); return; }
                principal = new("", 0, "operator");
            }
            string leaf = context.Request.Path.Value!.Split('/').Last();
            var query = new SemanticQuery(context.Request.QueryString.Value, leaf == "sigma-rules");
            bool exact = leaf is "scenarios" or "actions" && query.ExactEventId() is not null;
            var facts = await services.GetRequiredService<IAccessFactsRepository>().LoadAsync(principal, ct);
            var caps = new CapabilityComposer().Compose(facts); var access = new ReportEligibility().Compose(facts, caps);
            if (leaf == "sigma-live-rules")
            {
                if (!caps.IsOwner) { await Error(context, "platform_owner_required", 403); return; }
                var response = await services.GetRequiredService<SigmaProjection>().LiveRulesAsync(context, principal, mutation, ct);
                await DomainHttp.WriteAsync(context, response, 200, ct);
                return;
            }
            bool resourceAware = exact || leaf is "relations" or "sigma-rules" or "attack-coverage";
            // The platform-settings prefix has the same coarse access.manage gate as Python.
            string capability = leaf == "semantic-control" ? "access.manage" : "semantic.review";
            if (!resourceAware && !caps.Decide(capability).Allowed)
            {
                await DomainHttp.WriteAsync(context, new { error = caps.Decide(capability).Reason, required_capability = capability }, 403, ct); return;
            }
            if (leaf == "semantic-control" && !caps.IsOwner) { await Error(context, "platform_owner_required", 403); return; }
            if (exact && !caps.IsOwner)
                foreach (string required in SemanticWorkspace.ExactCapabilities)
                    if (!caps.Capabilities.Contains(required) && !caps.ResourceCapabilities.Contains(required))
                    { await DomainHttp.WriteAsync(context, new { error = "insufficient_capability", required_capability = required }, 403, ct); return; }
            JsonNode result; int status = 200;
            if (mutation)
            {
                using var body = await AuthJsonBody.ReadAsync(context, ct);
                var payload = JsonNode.Parse(body.RootElement.GetRawText())!.AsObject();
                var governance = services.GetRequiredService<SemanticGovernance>();
                if (leaf == "semantic-control")
                    result = await governance.ChangeAsync(payload, principal, policy.Resolve(context).Address, ct);
                else
                {
                    // Python's HTTP adapter coerces these fields before review validation.
                    foreach (string key in new[] { "verdict", "review_confidence", "rationale", "review_request_id" })
                        payload[key] = AuthJsonBody.CredentialString(body.RootElement, key);
                    result = await governance.ReviewAsync(context.Request.RouteValues["id"]?.ToString() ?? "", payload, principal, ct);
                    status = result.Flag("replayed") ? 200 : 201;
                }
            }
            else if (leaf == "semantic-control") result = await services.GetRequiredService<SemanticGovernance>().ListAsync(ct);
            else if (leaf is "sigma-rules" or "attack-coverage") result = await services.GetRequiredService<SigmaProjection>().ReadAsync(leaf, query, caps, ct);
            else if (leaf == "relations") result = await services.GetRequiredService<SemanticRelations>().ReadAsync(query, access, ct);
            else result = await services.GetRequiredService<SemanticWorkspace>().ReadAsync(leaf, query, caps, ct);
            await DomainHttp.WriteAsync(context, result, status, ct);
        }
        catch (SemanticInputException error) { await Error(context, error.Message, error.Status); }
        catch (AuthInputException error) { await Error(context, error.Code, error.StatusCode); }
        catch (PostgresException error) when (error.SqlState == "57014") { await DomainHttp.WriteAsync(context, new { error = "report_read_timeout", state = "unavailable" }, 503, ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception error) { if (context.Response.HasStarted) throw; await AuthResponse.UnexpectedAsync(context, error, ct, login: false); }
    }
    private static Task Error(HttpContext c, string code, int status) => DomainHttp.WriteAsync(c, new { error = code }, status, c.RequestAborted);
}
