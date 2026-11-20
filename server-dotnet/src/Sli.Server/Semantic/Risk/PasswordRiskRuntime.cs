using System.CommandLine;
using Sli.Server.Semantic.Password;

namespace Sli.Server.Semantic.Risk;

public sealed class PasswordRiskHostedService(PasswordRiskConsumer consumer,PasswordRiskOptions options,IHostApplicationLifetime lifetime,ILogger<PasswordRiskHostedService> logger):BackgroundService
{
    public int ExitCode {get;private set;}
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try {
            do {
                try {
                    var result=await consumer.RunOnceAsync(stoppingToken);ExitCode=result.Failed==0?0:1;
                    logger.LogInformation("password_risk_cycle claimed={Claimed} completed={Completed} failed={Failed} published={Published} pending={Pending} frozen={Frozen}",result.Claimed,result.Completed,result.Failed,result.Published,result.Pending,result.Frozen);
                }catch(OperationCanceledException)when(stoppingToken.IsCancellationRequested){throw;}
                catch{ExitCode=1;logger.LogWarning("password_risk_cycle_failed");}
                if(options.Once)break;await Task.Delay(TimeSpan.FromSeconds(Math.Clamp(options.PollSeconds,1,300)),stoppingToken);
            }while(!stoppingToken.IsCancellationRequested);
        }catch(OperationCanceledException)when(stoppingToken.IsCancellationRequested){}
        finally{if(options.Once)lifetime.StopApplication();}
    }
}

public static class PasswordRiskHosting
{
    public static IServiceCollection AddPasswordRiskConsumer(this IServiceCollection services,PasswordProducerRuntime runtime,PasswordRiskOptions options)
    {
        services.AddSingleton(runtime);services.AddSingleton(options);services.AddSingleton<PasswordRiskConsumer>();services.AddSingleton<PasswordRiskHostedService>();services.AddHostedService(sp=>sp.GetRequiredService<PasswordRiskHostedService>());return services;
    }
}

public static class PasswordRiskCommand
{
    public static async Task<int> RunAsync(string[] args)
    {
        var once=new Option<bool>("--once");var poll=new Option<int>("--poll-seconds"){DefaultValueFactory=_=>10};var limit=new Option<int>("--max-jobs"){DefaultValueFactory=_=>16};var lease=new Option<int>("--lease-seconds"){DefaultValueFactory=_=>300};
        var command=new RootCommand("Evaluate leased managed password brute-force v2 risk scenarios and publish qualified findings.");
        command.Options.Add(once);command.Options.Add(poll);command.Options.Add(limit);command.Options.Add(lease);
        command.SetAction(async(parse,ct)=>{
            await using var runtime=PasswordProducerRuntime.TryCreate();if(runtime==null){Console.Error.WriteLine("password_risk_worker_configuration_invalid");return 1;}
            var builder=Host.CreateApplicationBuilder(Array.Empty<string>());builder.Services.AddPasswordRiskConsumer(runtime,new(parse.GetValue(once),parse.GetValue(poll),parse.GetValue(limit),parse.GetValue(lease)));
            using var host=builder.Build();var service=host.Services.GetRequiredService<PasswordRiskHostedService>();await host.RunAsync(ct);return service.ExitCode;
        });
        return await command.Parse(args,new ParserConfiguration{ResponseFileTokenReplacer=null}).InvokeAsync(new InvocationConfiguration{EnableDefaultExceptionHandler=false});
    }
}
