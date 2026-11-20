namespace Sli.Server.Agents.Control;

public static class AgentLifecycleEndpoints
{
    public static IServiceCollection AddAgentLifecycleControl(this IServiceCollection services)
    { services.AddScoped<AgentLifecycleService>(); return services; }

    public static IEndpointRouteBuilder MapAgentLifecycleControlEndpoints(this IEndpointRouteBuilder endpoints)
    {
        const string removal = "/api/v1/admin/agents/remove", probe = "/api/v1/admin/agents/rights-probe";
        endpoints.MapPost(removal, (HttpContext context, AgentLifecycleService service) => AgentControlEndpoints.HandleAsync(context, removal,
            (db, tx, payload, actor, ct) => service.RequestRemovalAsync(db, tx, payload, actor, ct), platformOwnerOnly: true));
        endpoints.MapPost(probe, (HttpContext context, AgentLifecycleService service) => AgentControlEndpoints.HandleAsync(context, probe,
            (db, tx, payload, actor, ct) => service.RequestProbeAsync(db, tx, payload, actor, ct)));
        const string restore="/api/v1/admin/agents/restore";
        endpoints.MapPost(restore,(HttpContext context,AgentLifecycleService service)=>AgentControlEndpoints.HandleAsync(context,restore,
            (db,tx,payload,actor,ct)=>service.RestoreAsync(db,tx,payload,actor,ct),platformOwnerOnly:true));
        return endpoints;
    }
}
