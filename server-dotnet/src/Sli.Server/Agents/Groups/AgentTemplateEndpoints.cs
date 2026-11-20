using Sli.Server.Agents.Control;
namespace Sli.Server.Agents.Groups;

public static class AgentTemplateEndpoints
{
    public static IServiceCollection AddAgentTemplates(this IServiceCollection services)
    {services.AddScoped<AgentTemplateService>();return services;}
    public static IEndpointRouteBuilder MapAgentTemplateEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/v1/admin/agent-templates",List);
        endpoints.MapPost("/api/v1/admin/agent-templates",Save);
        return endpoints;
    }
    private static Task List(HttpContext context)=>AgentControlEndpoints.HandleAsync(context,"/api/v1/admin/agent-templates",
        (c,t,_,actor,ct)=>context.RequestServices.GetRequiredService<AgentTemplateService>().ListAsync(c,t,actor,ct),noStoreOnly:true);
    private static Task Save(HttpContext context)=>AgentControlEndpoints.HandleAsync(context,"/api/v1/admin/agent-templates",
        (c,t,body,actor,ct)=>context.RequestServices.GetRequiredService<AgentTemplateService>().SaveAsync(c,t,body,actor,ct),noStoreOnly:true);
}
