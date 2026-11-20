using Microsoft.AspNetCore.Http.Features;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Updates;
namespace Sli.Server.Agents;
public static class AgentUpdateAdministrationEndpoints
{
    private const string Packages="/api/v1/admin/agent-packages",Policy="/api/v1/admin/agents/update-policy",Waves="/api/v1/admin/agent-update-waves",Stop="/api/v1/admin/agent-update-waves/stop";
    public static IServiceCollection AddAgentUpdateAdministration(this IServiceCollection services)
    {services.AddScoped<AgentUpdateAdministration>();return services;}
    public static IEndpointRouteBuilder MapAgentUpdateAdministrationEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet(Packages,ListPackages);endpoints.MapPost(Packages,Upload);
        endpoints.MapPost(Policy,Assign);endpoints.MapGet(Waves,ListWaves);endpoints.MapPost(Waves,CreateWave);endpoints.MapPost(Stop,StopWave);return endpoints;
    }
    private static Task ListPackages(HttpContext c)
    {AgentControlEndpoints.ControlOperation operation=(db,tx,_,actor,ct)=>Service(c).ListPackagesAsync(db,tx,actor,ct);return AgentControlEndpoints.HandleAsync(c,Packages,operation);}
    private static Task Upload(HttpContext c)
    {AgentControlEndpoints.ControlRawOperation operation=async(db,tx,actor,ct)=>await Service(c).UploadAsync(db,tx,await ReadUploadAsync(c),actor,ct);return AgentControlEndpoints.HandleAsync(c,Packages,rawOperation:operation);}
    private static Task Assign(HttpContext c)
    {AgentControlEndpoints.ControlOperation operation=(db,tx,payload,actor,ct)=>Service(c).AssignAsync(db,tx,payload,actor,ct);return AgentControlEndpoints.HandleAsync(c,Policy,operation);}
    private static Task ListWaves(HttpContext c)
    {AgentControlEndpoints.ControlOperation operation=(db,tx,_,actor,ct)=>Service(c).ListWavesAsync(db,tx,AgentUpdateAdminInput.WaveQuery(c.Request.QueryString.Value??""),actor,ct);return AgentControlEndpoints.HandleAsync(c,Waves,operation);}
    private static Task CreateWave(HttpContext c)
    {AgentControlEndpoints.ControlOperation operation=(db,tx,payload,actor,ct)=>Service(c).CreateWaveAsync(db,tx,payload,actor,ct);return AgentControlEndpoints.HandleAsync(c,Waves,operation,platformOwnerOnly:true);}
    private static Task StopWave(HttpContext c)
    {AgentControlEndpoints.ControlOperation operation=(db,tx,payload,actor,ct)=>Service(c).StopWaveAsync(db,tx,payload,actor,ct);return AgentControlEndpoints.HandleAsync(c,Stop,operation,platformOwnerOnly:true);}
    private static AgentUpdateAdministration Service(HttpContext c)
    {c.Response.Headers.CacheControl="no-store";return c.RequestServices.GetRequiredService<AgentUpdateAdministration>();}
    internal static async Task<byte[]> ReadUploadAsync(HttpContext context)
    {
        if(context.Request.ContentLength is not long length || length is <1 or >268435456 || context.Request.Headers.TransferEncoding.ToString().Length>0 || context.Request.ContentType!="application/zip")throw new AgentControlException("agent_package_invalid");
        if(context.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly:false } limit)limit.MaxRequestBodySize=268435456;
        var raw=new byte[(int)length];int received=0;
        while(received<raw.Length){int read=await context.Request.Body.ReadAsync(raw.AsMemory(received),context.RequestAborted);if(read==0)throw new AgentControlException("agent_package_invalid");received+=read;}return raw;
    }
}
