using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Http.Features;
using Sli.Server.Agents.Control;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;
using Sli.Server.Infrastructure;

namespace Sli.Server.Agents.Groups;

public static class AgentGroupEndpoints
{
    public static IServiceCollection AddAgentGroups(this IServiceCollection services)
    {services.AddScoped<AgentGroupService>();return services;}
    public static IEndpointRouteBuilder MapAgentGroupEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/v1/admin/agent-group-tokens",List);
        endpoints.MapPost("/api/v1/admin/agent-group-tokens",Create);
        endpoints.MapPost("/api/v1/admin/agent-group-tokens/revoke",Revoke);
        endpoints.MapPost("/api/v1/admin/agent-group-requests",Pending);
        endpoints.MapPost("/api/v1/admin/agent-group-requests/approve",Approve);
        endpoints.MapGet("/api/v1/admin/agent-onboarding",Progress);
        endpoints.MapPost("/api/v1/admin/agent-onboarding/approve",Onboard);
        endpoints.MapPost("/api/v1/agent/group-enroll",Submit);
        return endpoints;
    }
    private static AgentGroupService Service(HttpContext c)=>c.RequestServices.GetRequiredService<AgentGroupService>();
    private static Task List(HttpContext c)=>AgentControlEndpoints.HandleAsync(c,"/api/v1/admin/agent-group-tokens",(db,tx,_,actor,ct)=>Service(c).ListAsync(db,tx,actor,ct),noStoreOnly:true);
    private static Task Create(HttpContext c)=>AgentControlEndpoints.HandleAsync(c,"/api/v1/admin/agent-group-tokens",(db,tx,b,actor,ct)=>Service(c).CreateAsync(db,tx,b,actor,ct),maxBodyBytes:512*1024,noStoreOnly:true);
    private static Task Revoke(HttpContext c)=>AgentControlEndpoints.HandleAsync(c,"/api/v1/admin/agent-group-tokens/revoke",(db,tx,b,actor,ct)=>Service(c).RevokeAsync(db,tx,b,actor,ct),maxBodyBytes:512*1024,noStoreOnly:true);
    private static Task Pending(HttpContext c)=>AgentControlEndpoints.HandleAsync(c,"/api/v1/admin/agent-group-requests",(db,tx,b,actor,ct)=>Service(c).PendingAsync(db,tx,b,actor,ct),noStoreOnly:true);
    private static Task Approve(HttpContext c)=>AgentControlEndpoints.HandleAsync(c,"/api/v1/admin/agent-group-requests/approve",(db,tx,b,actor,ct)=>Service(c).ApproveAsync(db,tx,b,actor,ct),maxBodyBytes:512*1024,noStoreOnly:true);
    private static Task Onboard(HttpContext c)=>AgentControlEndpoints.HandleAsync(c,"/api/v1/admin/agent-onboarding/approve",(db,tx,b,actor,ct)=>Service(c).OnboardAsync(db,tx,b,actor,ct),noStoreOnly:true);
    private static Task Progress(HttpContext c)=>AgentControlEndpoints.HandleAsync(c,"/api/v1/admin/agent-onboarding",(db,tx,_,actor,ct)=>
    {
        // Python parse_qs drops blank values and preserves repeated values.
        var pairs=(c.Request.QueryString.Value??"").TrimStart('?').Split('&').Select(x=>x.Split('=',2)).Where(x=>x.Length==2)
            .Select(x=>(Key:WebUtility.UrlDecode(x[0]),Value:WebUtility.UrlDecode(x[1]))).Where(x=>x.Value.Length>0).ToArray();
        if(pairs.Length!=1 || pairs[0].Key!="token_id")throw new AgentControlException("invalid_agent_batch_approval");
        return Service(c).ProgressAsync(db,tx,pairs[0].Value,actor,ct);
    },noStoreOnly:true);
    private static async Task Submit(HttpContext c)
    {
        var ct=c.RequestAborted;string raw=(c.Features.Get<IHttpRequestFeature>()?.RawTarget??c.Request.Path.Value??"").Split('?',2)[0];
        if(raw!="/api/v1/agent/group-enroll"){await DomainHttp.WriteAsync(c,new{error="not_implemented"},501,ct);return;}
        JsonDocument body;
        try{body=await AuthJsonBody.ReadAsync(c,ct);}
        catch(AuthInputException e){await DomainHttp.WriteAsync(c,new{error=e.Code},e.StatusCode,ct);return;}
        using(body)
        {
            c.Response.Headers.CacheControl="no-store";
            // Enrollment admits a not-yet-issued key. HTTPS is transport, not
            // user authority, forwarded certificate identity or approval.
            if(!c.Request.IsHttps){await DomainHttp.WriteAsync(c,new{error="agent_tls_required"},401,ct);return;}
            try
            {
                var durable=CancellationToken.None;
                await using var db=await c.RequestServices.GetRequiredService<IPostgresConnectionFactory>().OpenAsync(durable);
                await using var tx=await db.BeginTransactionAsync(durable);
                JsonElement output;int status=200;
                try{output=JsonSerializer.SerializeToElement(await Service(c).SubmitAsync(db,tx,body.RootElement,durable));}
                catch(AgentGroupAuditedRejection){output=JsonSerializer.SerializeToElement(new{error="group_enrollment_rejected"});status=401;}
                await tx.CommitAsync(durable);
                await DomainHttp.WriteAsync(c,output,status,ct);
            }
            catch(AgentControlException e){await DomainHttp.WriteAsync(c,new{error=e.Message},e.Status,ct);}
            catch(OperationCanceledException)when(ct.IsCancellationRequested){}
            catch(Exception)when(!c.Response.HasStarted){await DomainHttp.WriteAsync(c,new{error="agent_service_unavailable"},503,ct);}
        }
    }
}
