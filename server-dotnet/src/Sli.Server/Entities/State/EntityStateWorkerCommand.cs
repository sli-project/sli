using System.CommandLine;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Server.Entities.State;

internal sealed record EntityStateWorkerOptions(bool Once,int PollSeconds,int Limit);
internal delegate Task<int> EntityStateRunner(EntityStateWorkerOptions options,Action<JsonObject> output,CancellationToken ct);

// Dedicated process entrypoint; the worker itself owns the source advisory lock.
public static class EntityStateWorkerCommand
{
    public static Task<int> RunAsync(string[] args)=>RunCoreAsync(args,RunWorkerAsync,Console.Out,Console.Error);
    internal static async Task<int> RunCoreAsync(string[] args,EntityStateRunner runner,TextWriter output,TextWriter error,CancellationToken cancellationToken=default)
    {
        var once=new Option<bool>("--once");
        var poll=new Option<int>("--poll-seconds") { DefaultValueFactory=_=>30 };
        var limit=new Option<int>("--limit") { DefaultValueFactory=_=>16 };
        var supervisor=new Option<bool>("--load-supervisor-environment");
        var root=new RootCommand("Project durable entity-state jobs.");
        root.Options.Add(once);root.Options.Add(poll);root.Options.Add(limit);root.Options.Add(supervisor);
        root.SetAction(async (parse,ct)=> {
            // The legacy Windows DPAPI supervisor profile is not yet ported.
            if(parse.GetValue(supervisor)){await error.WriteLineAsync("entity_state_supervisor_environment_unavailable");return 1;}
            var options=new EntityStateWorkerOptions(parse.GetValue(once),Math.Clamp(parse.GetValue(poll),1,300),Math.Clamp(parse.GetValue(limit),1,16));
            var builder=Host.CreateApplicationBuilder(Array.Empty<string>());builder.Logging.ClearProviders();
            builder.Services.AddSingleton(options);builder.Services.AddSingleton(runner);
            builder.Services.AddSingleton(new EntityStateOutput(output,error));
            builder.Services.AddSingleton<EntityStateHostedService>();
            builder.Services.AddHostedService(sp=>sp.GetRequiredService<EntityStateHostedService>());
            using var host=builder.Build();var service=host.Services.GetRequiredService<EntityStateHostedService>();
            try {await host.RunAsync(ct);return service.ExitCode;}
            catch(OperationCanceledException) when(ct.IsCancellationRequested){return 0;}
        });
        var parsed=root.Parse(args,new ParserConfiguration { ResponseFileTokenReplacer=null });
        return await parsed.InvokeAsync(new InvocationConfiguration { EnableDefaultExceptionHandler=false },cancellationToken);
    }
    private static async Task<int> RunWorkerAsync(EntityStateWorkerOptions options,Action<JsonObject> output,CancellationToken ct)
    {
        await using var runtime=EntityStateWorkerRuntime.TryCreate() ?? throw new InvalidOperationException("server_configuration_invalid");
        return await new EntityStateWorker(runtime).RunAsync(options.Once,options.PollSeconds,options.Limit,ct,output);
    }
}
internal sealed record EntityStateOutput(TextWriter Output,TextWriter Error);
internal sealed class EntityStateHostedService(EntityStateRunner runner,EntityStateWorkerOptions options,EntityStateOutput streams,IHostApplicationLifetime lifetime) : BackgroundService
{
    internal int ExitCode {get;private set;}=1;
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try {ExitCode=await runner(options,value=>streams.Output.WriteLine(CanonicalJson.Serialize(value,ensureAscii:false)),stoppingToken);}
        catch(OperationCanceledException) when(stoppingToken.IsCancellationRequested){ExitCode=0;}
        catch(InvalidOperationException e) when(e.Message=="server_configuration_invalid") {await streams.Error.WriteLineAsync("server_configuration_invalid");}
        catch(Exception) {await streams.Error.WriteLineAsync("entity_state_worker_unavailable");}
        finally {lifetime.StopApplication();}
    }
}
