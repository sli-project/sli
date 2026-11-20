using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.AspNetCore.Http.Features;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Certificates;
using Sli.Server.Agents.Ingress;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;
using Sli.Server.Hosting;
using Sli.Server.Infrastructure;

namespace Sli.Server.Agents;

public static class AgentPacketEndpoints
{
    public static IServiceCollection AddAgentPacketIngress(this IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.AddSingleton(_ => AgentInboxLimits.FromEnvironment());
        services.AddSingleton(sp => new AgentIngressDiagnostics(
            AgentIngressDiagnostics.ResolveDataDirectory(sp.GetRequiredService<IHostEnvironment>().ContentRootPath),
            sp.GetRequiredService<ILogger<AgentIngressDiagnostics>>(), sp.GetRequiredService<TimeProvider>()));
        services.AddScoped<IAgentPacketService, AgentPacketService>();
        return services;
    }

    public static IEndpointRouteBuilder MapAgentPacketEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/api/v1/agent/packets", HandleAsync);
        return endpoints;
    }

    private static async Task HandleAsync(HttpContext context)
    {
        var ct = context.RequestAborted;
        string raw = context.Features.Get<IHttpRequestFeature>()?.RawTarget ?? context.Request.Path.Value ?? "";
        if (raw.Split('?', 2)[0] != "/api/v1/agent/packets")
        {
            await DomainHttp.WriteAsync(context, new { error = "not_implemented" }, 501, ct);
            return;
        }
        context.Response.Headers.CacheControl = "no-store";
        try
        {
            var peer = context.Request.IsHttps ? await context.Connection.GetClientCertificateAsync(ct) : null;
            if (peer is null || context.RequestServices.GetService<AgentTlsTrust>() is null)
                throw new AgentCertificateException("agent_mtls_required", 401);
            using var json = await AuthJsonBody.ReadAsync(context, ct);
            JsonNode packet = JsonNode.Parse(json.RootElement.GetRawText())!;
            var services = context.RequestServices;
            await using var connection = await services.GetRequiredService<IPostgresConnectionFactory>().OpenAsync(ct);
            await using var transaction = await connection.BeginTransactionAsync(ct);
            var identity = await services.GetRequiredService<IAgentIdentityService>().AuthenticateAsync(connection, transaction, peer, false, ct);
            var receipt = await services.GetRequiredService<IAgentPacketService>().ReceiveAsync(connection, transaction, identity, peer, packet, ct);
            await transaction.CommitAsync(ct);
            try
            {
                services.GetRequiredService<AgentIngressDiagnostics>().RejectionAfterCommit(identity, Envelope.Parse(packet["envelope"]), receipt);
            }
            catch (Exception) { /* Diagnostics must not alter a committed receipt. */ }
            await DomainHttp.WriteAsync(context, receipt, 200, ct);
        }
        catch (ProtocolException error)
        { await DomainHttp.WriteAsync(context, new { error = error.Code }, 400, ct); }
        catch (AuthInputException error)
        {
            context.Response.Headers.Remove("Cache-Control");
            await DomainHttp.WriteAsync(context, new { error = error.Code }, error.StatusCode, ct);
        }
        catch (AgentCertificateException error)
        { await DomainHttp.WriteAsync(context, new { error = "agent_authentication_failed" }, error.Status, ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception) when (!context.Response.HasStarted)
        { await DomainHttp.WriteAsync(context, new { error = "agent_service_unavailable" }, 503, ct); }
    }
}
