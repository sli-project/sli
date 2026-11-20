using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http.Features;
using Sli.Server.Agents.Certificates;
using Sli.Server.Agents.ClientControl;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Registry;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;
using Sli.Server.Hosting;
using Sli.Server.Infrastructure;

namespace Sli.Server.Agents.FileAudit;

internal static class FileAuditIngestEndpoint
{
    internal static async Task Handle(HttpContext context)
    {
        const string route="/api/v1/agent/file-audit-report";var ct=context.RequestAborted;
        string raw=(context.Features.Get<IHttpRequestFeature>()?.RawTarget ?? context.Request.Path.Value ?? "").Split('?',2)[0];
        if(raw!=route) { await DomainHttp.WriteAsync(context,new { error="not_implemented" },501,ct);return; }
        JsonNode? body;
        try { using var doc=await AuthJsonBody.ReadAsync(context,ct);body=AgentClientJson.FromElement(doc.RootElement); }
        catch(AuthInputException e) { await DomainHttp.WriteAsync(context,new { error=e.Code },e.StatusCode,ct);return; }
        context.Response.Headers.CacheControl="no-store";
        try
        {
            var peer=context.Request.IsHttps?await context.Connection.GetClientCertificateAsync(ct):null;
            if(peer is null || context.RequestServices.GetService<AgentTlsTrust>() is null) throw new AgentCertificateException("agent_mtls_required",401);
            var services=context.RequestServices; await using var db=await services.GetRequiredService<IPostgresConnectionFactory>().OpenAsync(ct);await using var tx=await db.BeginTransactionAsync(ct);
            var identity=await services.GetRequiredService<AgentIdentityService>().AuthenticateAsync(db,tx,peer,false,ct);
            var result=await services.GetRequiredService<FileAuditIngestService>().Ingest(db,tx,identity,body,ct);
            await tx.CommitAsync(ct);await DomainHttp.WriteAsync(context,result,200,ct);
        }
        catch(AgentCertificateException e) { await DomainHttp.WriteAsync(context,new { error=e.Code },e.Status,ct); }
        catch(AgentControlException e) { await DomainHttp.WriteAsync(context,new { error=e.Message },e.Status,ct); }
        catch(OperationCanceledException) when(ct.IsCancellationRequested) { }
        catch(Exception) when(!context.Response.HasStarted) { await DomainHttp.WriteAsync(context,new { error="agent_service_unavailable" },503,ct); }
    }
}
