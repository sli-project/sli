using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;
using Sli.Server.Infrastructure;

namespace Sli.Server.Agents.Control;

public static class AgentControlEndpoints
{
    public static IServiceCollection AddAgentControl(this IServiceCollection services)
    {
        services.TryAddScoped<IAccessFactsRepository, AccessFactsRepository>();
        services.TryAddSingleton<IAgentControlAudit, AgentControlAudit>(); services.AddScoped<AgentManagementService>(); services.AddScoped<IAgentPolicyService, AgentPolicyService>(); services.AddScoped<AgentModuleAssignmentService>(); return services;
    }
    public static IEndpointRouteBuilder MapAgentControlEndpoints(this IEndpointRouteBuilder endpoints)
    {
        foreach (string route in new[] { "/api/v1/admin/agents", "/api/v1/admin/agent-tokens" }) endpoints.MapGet(route, ctx => HandleAsync(ctx, route));
        foreach (string route in new[] { "/api/v1/admin/agent-tokens", "/api/v1/admin/agent-tokens/revoke", "/api/v1/admin/agents/revoke", "/api/v1/admin/agents/disable", "/api/v1/admin/agents/policy", "/api/v1/admin/agents/modules" }) endpoints.MapPost(route, ctx => HandleAsync(ctx, route));
        return endpoints;
    }
    internal delegate Task<JsonElement> ControlOperation(NpgsqlConnection db, NpgsqlTransaction tx, JsonElement payload, string actor, CancellationToken ct);
    internal delegate Task<JsonElement> ControlAuthorizedOperation(NpgsqlConnection db, NpgsqlTransaction tx, JsonElement payload, Principal principal, CapabilityDecisionSet access, CancellationToken ct);
    internal delegate Task<JsonElement> ControlRawOperation(NpgsqlConnection db, NpgsqlTransaction tx, string actor, CancellationToken ct);

    internal static async Task HandleAsync(HttpContext context, string route, ControlOperation? operation = null, bool platformOwnerOnly = false, ControlRawOperation? rawOperation = null, int maxBodyBytes = 65536, bool noStoreOnly = false, ControlAuthorizedOperation? authorizedOperation = null)
    {
        var ct = context.RequestAborted;
        bool executing = false;
        try
        {
            var services = context.RequestServices;
            string raw = (context.Features.Get<IHttpRequestFeature>()?.RawTarget ?? context.Request.Path.Value ?? "").Split('?', 2)[0];
            if (raw != route) { await DomainHttp.WriteAsync(context, new { error = "not_implemented" }, 501, ct); return; }
            var transport = services.GetRequiredService<TransportGate>(); var failure = transport.CheckTransport(context);
            if (failure is not null) { await AuthResponse.ErrorAsync(context, failure.Code, failure.StatusCode, ct); return; }
            var policy = services.GetRequiredService<AuthRequestPolicy>(); bool mutation = HttpMethods.IsPost(context.Request.Method);
            if (mutation && !policy.OriginAllowed(context, policy.Resolve(context))) { await AuthResponse.ErrorAsync(context, "cross_origin_request_rejected", 403, ct); return; }
            if (mutation && !policy.AuthRequired)
            {
                string expected = AgentControlJson.Strip(services.GetRequiredService<IConfiguration>()["Sli:OperatorToken"] ?? Environment.GetEnvironmentVariable("ADLOG_OPERATOR_TOKEN") ?? "");
                if (expected.Length > 0 && !CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(expected)), SHA256.HashData(Encoding.UTF8.GetBytes(context.Request.Headers["X-ADLog-Operator-Token"].ToString()))))
                { await DomainHttp.WriteAsync(context, new { error = "operator_token_required" }, 401, ct); return; }
            }
            // Source _owner always requires a real user/key principal, including
            // auth-off deployments, then platform owner OR access.manage.
            var result = await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context, ct);
            if (!result.Succeeded) { await AuthResponse.ErrorAsync(context, result.Failure?.Code ?? "authentication_required", result.Failure?.StatusCode ?? 401, ct); return; }
            var principal = result.Principal!; failure = TransportGate.CheckViewerRole(principal);
            if (failure is not null) { await AuthResponse.ErrorAsync(context, failure.Code, failure.StatusCode, ct); return; }
            var facts = await services.GetRequiredService<IAccessFactsRepository>().LoadAsync(principal, ct);
            if (!facts.IsOwner)
            {
                var decision = new CapabilityComposer().Compose(facts).Decide("access.manage");
                if (!decision.Allowed) { await DomainHttp.WriteAsync(context, new { error = decision.Reason, required_capability = "access.manage" }, 403, ct); return; }
            }
            if (platformOwnerOnly && !facts.IsOwner)
            { await DomainHttp.WriteAsync(context, new { error = "platform_owner_required" }, 403, ct); return; }
            string actor = principal.Type + ":" + principal.Id.ToString(System.Globalization.CultureInfo.InvariantCulture);
            using var body = mutation && rawOperation is null ? await AuthJsonBody.ReadAsync(context, ct, maxBodyBytes) : null;
            // Like source's synchronous _execute, accepted operations commit all
            // their writes/audit before any token/result is returned.
            var durable = mutation ? CancellationToken.None : ct;
            if (noStoreOnly) context.Response.Headers.CacheControl = "no-store";
            executing = true;
            await using var db = await services.GetRequiredService<IPostgresConnectionFactory>().OpenAsync(durable);
            await using var tx = await db.BeginTransactionAsync(durable);
            var management = services.GetRequiredService<AgentManagementService>();
            var output = authorizedOperation is not null ? await authorizedOperation(db, tx, body is null ? default : body.RootElement, principal, new CapabilityComposer().Compose(facts), durable) : rawOperation is not null ? await rawOperation(db, tx, actor, durable) : operation is not null ? await operation(db, tx, body is null ? default : body.RootElement, actor, durable) : (context.Request.Method, route) switch
            {
                ("GET", "/api/v1/admin/agents") => await management.ListAgentsAsync(db, tx, Values(context, "agent_id").FirstOrDefault(), actor, durable),
                ("GET", _) => await management.ListTokensAsync(db, tx, actor, durable),
                ("POST", "/api/v1/admin/agent-tokens") => await management.CreateTokenAsync(db, tx, body!.RootElement, actor, durable),
                ("POST", "/api/v1/admin/agent-tokens/revoke") => await management.RevokeTokenAsync(db, tx, body!.RootElement, actor, durable),
                ("POST", "/api/v1/admin/agents/policy") => await services.GetRequiredService<IAgentPolicyService>().UpdateControlAsync(db, tx, body!.RootElement, actor, durable),
                ("POST", "/api/v1/admin/agents/modules") => await services.GetRequiredService<AgentModuleAssignmentService>().AssignAsync(db, tx, body!.RootElement, actor, durable),
                _ => await management.RevokeAsync(db, tx, body!.RootElement, actor, route.EndsWith("/disable", StringComparison.Ordinal), durable)
            };
            await tx.CommitAsync(durable); await DomainHttp.WriteAsync(context, output, 200, ct);
        }
        catch (AgentControlException error) { await DomainHttp.WriteAsync(context, new { error = error.Message }, error.Status, ct); }
        catch (AuthInputException error) { await DomainHttp.WriteAsync(context, new { error = error.Code }, error.StatusCode, ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception error)
        {
            if (context.Response.HasStarted) throw;
            if (executing) await DomainHttp.WriteAsync(context, new { error = "agent_service_unavailable" }, 503, ct);
            else await DomainHttp.WriteUnexpectedAsync(context, context.RequestServices.GetRequiredService<ILogger<AgentManagementService>>(), error, ct, route);
        }
    }
    private static string[] Values(HttpContext context, string key) => (context.Request.QueryString.Value is { Length: > 0 } query ? query[1..] : "")
        .Split('&').Select(pair => pair.Split('=', 2)).Where(pair => pair.Length == 2 && WebUtility.UrlDecode(pair[0]) == key)
        .Select(pair => WebUtility.UrlDecode(pair[1])).Where(value => value.Length > 0).ToArray();
}

