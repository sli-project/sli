using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sli.Server.Access;
using Sli.Server.Agents.Control;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;

namespace Sli.Server.Agents.Deployment;

public static class AgentDeploymentEndpoints
{
    private const string Credentials = "/api/v1/ad-operation-credentials";
    private const string Directory = "/api/v1/admin/agent-deployment-directory";
    private const string Gpo = "/api/v1/agent-deployment/gpo/";
    public static IServiceCollection AddAgentDeployment(this IServiceCollection services)
    {
        services.TryAddScoped<IAccessFactsRepository, AccessFactsRepository>();
        services.TryAddScoped<IAgentDeploymentDatabase, AgentDeploymentDatabase>();
        services.TryAddSingleton<IAdCredentialSecrets, AdCredentialSecrets>();
        services.AddScoped<AdOperationCredentials>();
        services.AddScoped<AgentDeploymentDirectory>();
        services.AddScoped<AgentGpoPlans>();
        return services;
    }
    public static IEndpointRouteBuilder MapAgentDeploymentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet(Credentials, c => Handle(c, Credentials));
        foreach (string route in new[] { Credentials, Credentials + "/check", Credentials + "/replace-password", Credentials + "/delete", Directory, Gpo + "credentials", Gpo + "preview", Gpo + "confirm", Gpo + "cancel" })
            endpoints.MapPost(route, c => Handle(c, route));
        return endpoints;
    }
    internal static async Task Handle(HttpContext context, string route)
    {
        var ct = context.RequestAborted;
        context.Response.Headers.CacheControl = "no-store";
        try
        {
            string raw = (context.Features.Get<IHttpRequestFeature>()?.RawTarget ?? context.Request.Path.Value ?? "").Split('?', 2)[0];
            if (raw != route) { await DomainHttp.WriteAsync(context, new { error = "not_found" }, 404, ct); return; }
            var services = context.RequestServices;
            var failure = services.GetRequiredService<TransportGate>().CheckTransport(context);
            if (failure is not null) { await AuthResponse.ErrorAsync(context, failure.Code, failure.StatusCode, ct); return; }
            bool mutation = HttpMethods.IsPost(context.Request.Method);
            var policy = services.GetRequiredService<AuthRequestPolicy>();
            if (mutation && !policy.OriginAllowed(context, policy.Resolve(context))) { await AuthResponse.ErrorAsync(context, "cross_origin_request_rejected", 403, ct); return; }
            if (mutation && !policy.AuthRequired)
            {
                string token = AgentControlJson.Strip(services.GetRequiredService<IConfiguration>()["Sli:OperatorToken"] ?? Environment.GetEnvironmentVariable("ADLOG_OPERATOR_TOKEN") ?? "");
                if (token.Length > 0 && !CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(token)), SHA256.HashData(Encoding.UTF8.GetBytes(context.Request.Headers["X-ADLog-Operator-Token"].ToString()))))
                { await AuthResponse.ErrorAsync(context, "operator_token_required", 401, ct); return; }
            }
            var auth = await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context, ct);
            if (!auth.Succeeded) { await AuthResponse.ErrorAsync(context, auth.Failure?.Code ?? "authentication_required", auth.Failure?.StatusCode ?? 401, ct); return; }
            var principal = auth.Principal!;
            failure = TransportGate.CheckViewerRole(principal);
            if (failure is not null) { await AuthResponse.ErrorAsync(context, failure.Code, failure.StatusCode, ct); return; }
            if (route == Directory)
            {
                var facts = await services.GetRequiredService<IAccessFactsRepository>().LoadAsync(principal, ct);
                if (!facts.IsOwner)
                {
                    var decision = new CapabilityComposer().Compose(facts).Decide("access.manage");
                    if (!decision.Allowed) { await DomainHttp.WriteAsync(context, new { error = decision.Reason, required_capability = "access.manage" }, 403, ct); return; }
                }
            }
            else if (principal.Type != "session")
            { await DomainHttp.WriteAsync(context, new { error = route.StartsWith(Gpo, StringComparison.Ordinal) ? "gpo_session_required" : "ad_operations_denied" }, 403, ct); return; }
            if (!mutation && context.Request.Query.Any(x => x.Value.Any(v => !string.IsNullOrEmpty(v)))) throw new AgentControlException("ad_credential_request_invalid");
            using var document = mutation ? await AuthJsonBody.ReadAsync(context, ct) : null;
            // Enrollment TLS is checked on the actual connection; proxy headers
            // cannot authorize password delivery, including on an auth-off copy.
            if (mutation && route.StartsWith(Credentials, StringComparison.Ordinal) && !context.Request.IsHttps) throw new AgentControlException("agent_tls_required", 401);
            JsonObject body = document is null ? new() : Compatibility.PythonJson.FromElement(document.RootElement)!.AsObject();
            string actor = principal.Type + ":" + principal.Id.ToString(System.Globalization.CultureInfo.InvariantCulture);
            // Even a rejected metadata read can append the source's safe audit.
            var durable = CancellationToken.None;
            var db = services.GetRequiredService<IAgentDeploymentDatabase>();
            await db.OpenAsync(durable);
            JsonObject output; int status = 200;
            try
            {
                var credentials = services.GetRequiredService<AdOperationCredentials>();
                output = route switch
                {
                    Directory => await services.GetRequiredService<AgentDeploymentDirectory>().Read(body, durable),
                    Credentials when !mutation => await credentials.List(actor, durable),
                    Credentials => await credentials.Create(body, actor, durable),
                    _ when route.StartsWith(Credentials, StringComparison.Ordinal) => await credentials.Change(route[(Credentials.Length + 1)..], body, actor, durable),
                    _ when route == Gpo + "credentials" => await services.GetRequiredService<AgentGpoPlans>().Options(body, actor, durable),
                    _ when route == Gpo + "preview" => await services.GetRequiredService<AgentGpoPlans>().Preview(body, actor, durable),
                    _ => await services.GetRequiredService<AgentGpoPlans>().Finish(body, actor, route == Gpo + "cancel", durable)
                };
            }
            catch (AgentDeploymentRejection e) { output = new() { ["error"] = e.Message }; status = e.Status; }
            await db.CommitAsync(durable);
            await DomainHttp.WriteAsync(context, output, status, ct);
        }
        catch (AgentControlException e) { await DomainHttp.WriteAsync(context, new { error = e.Message }, e.Status, ct); }
        catch (AuthInputException e) { await DomainHttp.WriteAsync(context, new { error = e.Code }, e.StatusCode, ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        // PostgreSQL/crypto errors may include bind values. Keep diagnostics fixed.
        catch (Exception) when (!context.Response.HasStarted) { await DomainHttp.WriteAsync(context, new { error = "agent_service_unavailable" }, 503, ct); }
    }
}
