using System.Text.Json;
using Npgsql;
namespace Sli.Server.Notifications;

// Native notification-delivery replacement: the database arbitrates fairness
// across alerts/reports and bot cooldown across all workers and restarts.
public sealed class NotificationDeliveryWorker(NotificationDatabase database,SmtpWorker smtp,TelegramWorker telegram)
{
    public const string ClaimSql="""
        select id,subscription_id,subscription_revision,object_kind,object_id,recipient_user_id,
            attempts,lease_token,created_at,object_severity,delivery_reason,delay_minutes,channel
        from public.notification_claim_fair()
        """;
    public async Task<bool> ProcessAsync(CancellationToken ct)
    {
        NotificationJob? job=null;
        await using(var db=await database.OpenAsync(ct)) {
            await using var tx=await db.BeginTransactionAsync(ct);await using var cmd=new NpgsqlCommand(ClaimSql,db,tx);
            await using(var r=await cmd.ExecuteReaderAsync(ct)) {
                if(await r.ReadAsync(ct))job=new(r.GetGuid(0),r.GetGuid(1),r.GetInt64(2),r.GetString(3),r.GetGuid(4),r.GetInt64(5),r.GetInt32(6),r.GetGuid(7),r.GetDateTime(8),r.IsDBNull(9)?null:r.GetString(9),r.GetString(10),r.GetInt32(11)){Channel=r.GetString(12)};
            }
            await tx.CommitAsync(ct);
        }
        if(job is null)return false;
        return job.Channel switch {"smtp"=>await smtp.ProcessClaimedAsync(job,CancellationToken.None),"telegram"=>await telegram.ProcessClaimedAsync(job,CancellationToken.None),_=>throw new InvalidOperationException("invalid_notification_channel")};
    }
}
public sealed record NotificationDeliveryOptions(bool Once);
public sealed class NotificationDeliveryHostedService(NotificationDeliveryWorker worker,NotificationDeliveryOptions options,IHostApplicationLifetime lifetime,ILogger<NotificationDeliveryHostedService> logger):BackgroundService
{
    public int ExitCode {get;private set;}
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try {
            do {
                bool worked=false;
                try {
                    worked=await worker.ProcessAsync(stoppingToken);ExitCode=0;
                    string path=Environment.GetEnvironmentVariable("SLI_NOTIFICATION_STATUS_FILE")??Path.Combine(Path.GetTempPath(),"notification-delivery.json");
                    string tmp=Path.ChangeExtension(path,".tmp");await File.WriteAllTextAsync(tmp,JsonSerializer.Serialize(new {pid=Environment.ProcessId,at=DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()/1000.0}),CancellationToken.None);File.Move(tmp,path,true);
                }
                catch(OperationCanceledException) when(stoppingToken.IsCancellationRequested){throw;}
                catch {ExitCode=1;logger.LogWarning("notification_delivery_cycle_failed");}
                if(options.Once)break;if(!worked)await Task.Delay(3000,stoppingToken);
            }while(!stoppingToken.IsCancellationRequested);
        }
        catch(OperationCanceledException) when(stoppingToken.IsCancellationRequested){}
        finally {if(options.Once)lifetime.StopApplication();}
    }
}
public static class NotificationDeliveryCommand
{
    public static async Task<int> RunAsync(string[] args)
    {
        if(args.Length>1 || args.Any(x=>x!="--once")){Console.Error.WriteLine("notification_delivery_arguments_invalid");return 1;}
        await using var database=NotificationDatabase.TryCreate();if(database is null){Console.Error.WriteLine("notification_delivery_configuration_invalid");return 1;}
        var builder=Host.CreateApplicationBuilder(Array.Empty<string>());builder.Services.AddSingleton(database);builder.Services.AddSingleton(new NotificationDeliveryOptions(args.Length==1));
        builder.Services.AddSingleton<ISmtpSessionFactory,MailKitSmtpSessionFactory>();builder.Services.AddSingleton<SmtpSender>();builder.Services.AddSingleton<SmtpWorker>();builder.Services.AddSingleton<TelegramRequestState>();
        builder.Services.AddHttpClient("notification-telegram",client=>client.Timeout=Timeout.InfiniteTimeSpan).RemoveAllLoggers().ConfigurePrimaryHttpMessageHandler(sp=>TelegramWorkerCommand.CreateHandler(sp.GetRequiredService<TelegramRequestState>()));
        builder.Services.AddSingleton<TelegramSender>();builder.Services.AddSingleton<TelegramWorker>();builder.Services.AddSingleton<NotificationDeliveryWorker>();builder.Services.AddSingleton<NotificationDeliveryHostedService>();builder.Services.AddHostedService(sp=>sp.GetRequiredService<NotificationDeliveryHostedService>());
        if (args.Length == 0) builder.Services.AddHostedService<TelegramUpdateWorker>();
        using var host=builder.Build();var service=host.Services.GetRequiredService<NotificationDeliveryHostedService>();await host.RunAsync();return service.ExitCode;
    }
}
