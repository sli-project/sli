using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http.Features;
using Sli.Server.Agents.Certificates;
using Sli.Server.Agents.Registry;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;
using Sli.Server.Hosting;
using Sli.Server.Infrastructure;

namespace Sli.Server.Agents;

public static class AgentEnrollmentEndpoints
{
    public static IServiceCollection AddAgentEnrollment(this IServiceCollection services)
    {
        services.AddScoped(_ => AgentIssuingCa.FromEnvironment());
        services.AddSingleton<AgentLinkHistory>();
        services.AddScoped<AgentIdentityService>();
        services.AddScoped<IAgentIdentityService>(sp => sp.GetRequiredService<AgentIdentityService>());
        services.AddScoped<AgentEnrollmentService>();
        services.AddSingleton<AgentRegistrationReconciliation>();
        services.AddHostedService(sp => sp.GetRequiredService<AgentRegistrationReconciliation>());
        return services;
    }

    public static IEndpointRouteBuilder MapAgentEnrollmentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/api/v1/agent/enroll", context => HandleAsync(context, false));
        endpoints.MapPost("/api/v1/agent/renew", context => HandleAsync(context, true));
        return endpoints;
    }

    private static async Task HandleAsync(HttpContext context, bool renew)
    {
        CancellationToken ct = context.RequestAborted;
        string raw = context.Features.Get<IHttpRequestFeature>()?.RawTarget ?? context.Request.Path.Value ?? "";
        if (raw.Split('?', 2)[0] != (renew ? "/api/v1/agent/renew" : "/api/v1/agent/enroll"))
        {
            await DomainHttp.WriteAsync(context, new { error = "not_implemented" }, 501, ct);
            return;
        }
        JsonObject body;
        try
        {
            using var doc = await AuthJsonBody.ReadAsync(context, ct);
            body = JsonNode.Parse(doc.RootElement.GetRawText())!.AsObject();
        }
        catch (AuthInputException error)
        {
            await DomainHttp.WriteAsync(context, new { error = error.Code }, error.StatusCode, ct);
            return;
        }
        context.Response.Headers.CacheControl = "no-store";
        try
        {
            if (!context.Request.IsHttps) throw new AgentCertificateException(renew ? "agent_mtls_required" : "agent_tls_required", 401);
            var peer = renew ? await context.Connection.GetClientCertificateAsync(ct) : null;
            if (renew && (peer is null || context.RequestServices.GetService<AgentTlsTrust>() is null))
                throw new AgentCertificateException("agent_mtls_required", 401);
            var services = context.RequestServices;
            await using var connection = await services.GetRequiredService<IPostgresConnectionFactory>().OpenAsync(ct);
            await using var transaction = await connection.BeginTransactionAsync(ct);
            var enrollment = services.GetRequiredService<AgentEnrollmentService>();
            JsonObject result = renew
                ? await enrollment.RenewAsync(connection, transaction, peer!, body, ct)
                : await enrollment.EnrollAsync(connection, transaction, body, ct);
            await transaction.CommitAsync(ct);
            await DomainHttp.WriteAsync(context, result, result["error"]?.GetValue<string>()=="agent_identity_computer_conflict" ? 409 : 200, ct);
        }
        catch (AgentCertificateException error)
        {
            await DomainHttp.WriteAsync(context, new { error = error.Code }, error.Status, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception) when (!context.Response.HasStarted)
        {
            await DomainHttp.WriteAsync(context, new { error = "agent_service_unavailable" }, 503, ct);
        }
    }
}
