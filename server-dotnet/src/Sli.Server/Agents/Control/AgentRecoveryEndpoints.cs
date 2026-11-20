using System.Net;

namespace Sli.Server.Agents.Control;

public static class AgentRecoveryEndpoints
{
    private const string Recovery = "/api/v1/admin/agents/sequence-recovery", Replacement = "/api/v1/admin/agents/replace";
    public static IServiceCollection AddAgentRecoveryControl(this IServiceCollection services)
    { services.AddScoped<AgentRecoveryService>(); services.AddScoped<AgentReplacementService>(); return services; }
    public static IEndpointRouteBuilder MapAgentRecoveryControlEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet(Recovery,(HttpContext context,AgentRecoveryService service) => AgentControlEndpoints.HandleAsync(context,Recovery,
            (db,tx,_,actor,ct) => service.ListAsync(db,tx,AgentId(context),ct),platformOwnerOnly:true));
        endpoints.MapPost(Recovery,(HttpContext context,AgentRecoveryService service) => AgentControlEndpoints.HandleAsync(context,Recovery,
            (db,tx,payload,actor,ct) => service.AuthorizeAsync(db,tx,payload,actor,ct),platformOwnerOnly:true));
        endpoints.MapPost(Replacement,(HttpContext context,AgentReplacementService service) => AgentControlEndpoints.HandleAsync(context,Replacement,
            (db,tx,payload,actor,ct) => service.ReplaceAsync(db,tx,payload,actor,ct)));
        return endpoints;
    }
    private static string AgentId(HttpContext context)
    {
        // Source parse_qs drops blank values; an extra nonblank query key or a
        // repeated agent_id is rejected rather than selecting an arbitrary ID.
        string query = context.Request.QueryString.Value ?? "";
        var values = (query.Length > 0 ? query[1..] : "").Split('&')
            .Select(part => part.Split('=',2)).Where(part => part.Length == 2)
            .Select(part => (Key:WebUtility.UrlDecode(part[0]),Value:WebUtility.UrlDecode(part[1])))
            .Where(part => part.Value.Length > 0).ToArray();
        if (values.Length != 1 || values[0].Key != "agent_id") throw new AgentControlException("agent_sequence_recovery_invalid");
        return values[0].Value;
    }
}