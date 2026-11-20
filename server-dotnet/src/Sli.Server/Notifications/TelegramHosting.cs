using System.Text.Json;
namespace Sli.Server.Notifications;
public sealed record TelegramWorkerOptions(bool Once);
public sealed class TelegramHostedService(TelegramWorker worker,TelegramWorkerOptions options,IHostApplicationLifetime lifetime,ILogger<TelegramHostedService> logger):BackgroundService
{
    public int ExitCode {get;private set;}
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try {
            do {
                bool worked=false;
                try {
                    worked=await worker.ProcessAsync(stoppingToken);ExitCode=0;
                    string? path=Environment.GetEnvironmentVariable("SLI_NOTIFICATION_STATUS_FILE");
                    if(!string.IsNullOrEmpty(path)) {
                        string tmp=Path.ChangeExtension(path,".tmp");
                        await File.WriteAllTextAsync(tmp,JsonSerializer.Serialize(new {pid=Environment.ProcessId,at=DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()/1000.0}),CancellationToken.None);
                        File.Move(tmp,path,true);
                    }
                }catch(OperationCanceledException) when(stoppingToken.IsCancellationRequested){throw;}
                catch {ExitCode=1;logger.LogWarning("telegram_delivery_cycle_failed");}
                if(options.Once)break;
                if(!worked)await Task.Delay(TimeSpan.FromSeconds(3),stoppingToken);
            }while(!stoppingToken.IsCancellationRequested);
        }catch(OperationCanceledException) when(stoppingToken.IsCancellationRequested){}
        finally {if(options.Once)lifetime.StopApplication();}
    }
}
public static class TelegramWorkerCommand
{
    public static SocketsHttpHandler CreateHandler(TelegramRequestState state) =>
        new() {AllowAutoRedirect=false,UseCookies=false,MaxResponseHeadersLength=32,AutomaticDecompression=System.Net.DecompressionMethods.None,ConnectTimeout=TimeSpan.FromSeconds(5),Proxy=state,UseProxy=true,PlaintextStreamFilter=state.ConnectedStream};
    public static async Task<int> RunAsync(string[] args)
    {
        if(args.Any(x=>x!="--once") || args.Length>1){Console.Error.WriteLine("telegram_delivery_arguments_invalid");return 1;}
        await using var database=NotificationDatabase.TryCreate();if(database is null){Console.Error.WriteLine("telegram_delivery_configuration_invalid");return 1;}
        var builder=Host.CreateApplicationBuilder(Array.Empty<string>());
        builder.Services.AddSingleton(database);builder.Services.AddSingleton(new TelegramWorkerOptions(args.Length==1));builder.Services.AddSingleton<TelegramRequestState>();
        builder.Services.AddHttpClient("notification-telegram",client=>client.Timeout=Timeout.InfiniteTimeSpan).RemoveAllLoggers()
            .ConfigurePrimaryHttpMessageHandler(sp=>CreateHandler(sp.GetRequiredService<TelegramRequestState>()));
        builder.Services.AddSingleton<TelegramSender>();builder.Services.AddSingleton<TelegramWorker>();builder.Services.AddSingleton<TelegramHostedService>();builder.Services.AddHostedService(sp=>sp.GetRequiredService<TelegramHostedService>());
        using var host=builder.Build();var service=host.Services.GetRequiredService<TelegramHostedService>();await host.RunAsync();return service.ExitCode;
    }
}
