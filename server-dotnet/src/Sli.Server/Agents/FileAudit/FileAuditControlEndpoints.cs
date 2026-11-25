using System.Text.Json.Nodes;
using Sli.Server.Agents.Control;

namespace Sli.Server.Agents.FileAudit;

public static class FileAuditControlEndpoints
{
    public static IServiceCollection AddFileAuditControl(this IServiceCollection services) { services.AddScoped<FileAuditControlService>(); services.AddSingleton<FileAuditHookAdmission>(); services.AddScoped<FileAuditAdEnrichment>(); services.AddScoped<FileAuditIngestService>(); return services; }
    public static IEndpointRouteBuilder MapFileAuditControlEndpoints(this IEndpointRouteBuilder endpoints)
    {
        const string route="/api/v1/admin/agents/file-audit";
        endpoints.MapGet(route,(HttpContext context,FileAuditControlService service,FileAuditHookAdmission admission)=>AgentControlEndpoints.HandleAsync(context,route,authorizedOperation:async (db,tx,_,principal,access,ct)=>
        {
            var pairs=(context.Request.QueryString.Value ?? "").TrimStart('?').Split('&',StringSplitOptions.RemoveEmptyEntries).Select(x=>x.Split('=',2)).Where(x=>x.Length==2 && x[1].Length>0).Select(x=>(Key:System.Net.WebUtility.UrlDecode(x[0]),Value:System.Net.WebUtility.UrlDecode(x[1]))).ToArray();
            if(pairs.Length!=1 || pairs[0].Key!="agent_id") throw new AgentControlException("file_audit_request_invalid");
            using var guard=admission.Enter("audit_status"); return await service.Status(db,tx,pairs[0].Value,principal,access,ct);
        }));
        endpoints.MapPost(route,(HttpContext context,FileAuditControlService service,FileAuditHookAdmission admission)=>AgentControlEndpoints.HandleAsync(context,route,authorizedOperation:async (db,tx,payload,principal,access,ct)=>
        {
            var body=Sli.Server.Compatibility.PythonJson.FromElement(payload) as JsonObject;
            using var guard=admission.Enter(body?.ContainsKey("agents")==true ? "enqueue_audit_batch" : "enqueue_audit");
            if(body is null) throw new AgentControlException("file_audit_request_invalid");
            return body.ContainsKey("agents") ? await service.Batch(db,tx,body,principal,access,ct) : await service.Enqueue(db,tx,body,principal,access,ct);
        }));
        endpoints.MapPost("/api/v1/agent/file-audit-report",FileAuditIngestEndpoint.Handle);
        endpoints.MapGet(FileAuditCatalog.AdminRoute, (HttpContext context) => FileAuditCatalog.Admin(context));
        endpoints.MapPost(FileAuditCatalog.AdminRoute, (HttpContext context) => FileAuditCatalog.Admin(context));
        endpoints.MapPost(FileAuditCatalog.ReportRoute, (HttpContext context) => FileAuditCatalog.Report(context));
        return endpoints;
    }
}





