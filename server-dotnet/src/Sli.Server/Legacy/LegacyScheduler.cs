using Npgsql;
using Sli.Server.Infrastructure;

namespace Sli.Server.Legacy;

// Default-off diagnostic scheduler. The lock is held from admission through the
// terminal collection result, identically to the independent worker/manual path.
public sealed class LegacyScheduler(IServiceScopeFactory scopes, LegacySettings settings, ILogger<LegacyScheduler> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (settings.SchedulerBlock is not null) return;
        int interval = Integer("ADLOG_COLLECTION_INTERVAL_SECONDS",600,1);
        while (!stoppingToken.IsCancellationRequested) {
            try {
                if (settings.SchedulerBlock is not null) return;
                await using var scope = scopes.CreateAsyncScope();
                await using var db = await scope.ServiceProvider.GetRequiredService<IPostgresConnectionFactory>().OpenAsync(stoppingToken);
                await using var acquire = new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_collection_worker'))",db);
                if (await acquire.ExecuteScalarAsync(stoppingToken) is true) {
                    try {
                        bool canary = settings.Enabled("ADLOG_SCHEDULER_CANARY") || settings.Enabled("ADLOG_POSTGRES_SCHEDULER_CANARY");
                        int hours = canary ? Integer("ADLOG_CANARY_HOURS",1,1) : 1;
                        int events = canary ? Math.Min(Integer("ADLOG_CANARY_MAX_EVENTS",1000,1),Integer("ADLOG_CANARY_MAX_EVENTS_CAP",5000,1))
                            : Integer("ADLOG_ARCHIVE_MAX_EVENTS_PER_CHANNEL",500,1);
                        var job = await scope.ServiceProvider.GetRequiredService<LegacyJobs>().CreateScheduledAsync(new([],hours,events),stoppingToken);
                        if (job["id"] is {} id && job["status"]?.GetValue<string>() == "queued") {
                            var servers = job["servers"]!.AsArray().Select(n=>n!.GetValue<string>()).ToArray();
                            await scope.ServiceProvider.GetRequiredService<LegacyJobExecution>().RunAsync(new(id.GetValue<int>(),true,new(servers,hours,events),"scheduled"),stoppingToken,true);
                        }
                    }
                    finally {
                        await using var release = new NpgsqlCommand("select pg_advisory_unlock(hashtext('ad_log_reports_runtime_collection_worker'))",db);
                        await release.ExecuteScalarAsync(CancellationToken.None);
                    }
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
            catch { logger.LogWarning("scheduler_iteration_failed"); }
            await Task.Delay(TimeSpan.FromSeconds(interval),stoppingToken);
        }
    }
    private int Integer(string key,int fallback,int minimum) => Math.Max(minimum,int.TryParse(settings.Get(key),out var value) ? value : fallback);
}
