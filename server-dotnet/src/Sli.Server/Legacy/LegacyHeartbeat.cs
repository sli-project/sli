using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Infrastructure;

namespace Sli.Server.Legacy;

public interface ILegacyHeartbeat
{
    Task WriteAsync(string name,string worker,string status,string phase,int interval,JsonObject details,CancellationToken ct);
}

public sealed class LegacyHeartbeat(IPostgresConnectionFactory connections) : ILegacyHeartbeat
{
    private readonly DateTime started = DateTime.UtcNow;
    public async Task WriteAsync(string name,string worker,string status,string phase,int interval,JsonObject details,CancellationToken ct)
    {
        await using var db = await connections.OpenAsync(ct);
        await using var command = new NpgsqlCommand("""
            insert into runtime_worker_heartbeats(worker_name,worker_id,process_pid,status,phase,expected_interval_seconds,
              details_json,started_at,heartbeat_at,updated_at)
            values(@name,@worker,@pid,@status,@phase,@interval,@details,@started,now(),now())
            on conflict(worker_name) do update set worker_id=excluded.worker_id,process_pid=excluded.process_pid,
              status=excluded.status,phase=excluded.phase,expected_interval_seconds=excluded.expected_interval_seconds,
              details_json=excluded.details_json,started_at=excluded.started_at,heartbeat_at=now(),updated_at=now()
            """,db);
        command.Parameters.AddWithValue("name",name); command.Parameters.AddWithValue("worker",worker);
        command.Parameters.AddWithValue("pid",Environment.ProcessId); command.Parameters.AddWithValue("status",status);
        command.Parameters.AddWithValue("phase",phase); command.Parameters.AddWithValue("interval",Math.Clamp(interval,1,86400));
        command.Parameters.AddWithValue("details",NpgsqlDbType.Jsonb,details.ToJsonString()); command.Parameters.AddWithValue("started",started);
        await command.ExecuteNonQueryAsync(ct);
    }
}

public sealed class LegacyPostCollectionHostedService(IServiceScopeFactory scopes,LegacySettings settings,ILogger<LegacyPostCollectionHostedService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try { await RunAsync(stoppingToken); }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        catch { logger.LogWarning("post_collection_inprocess_unavailable"); }
    }
    private async Task RunAsync(CancellationToken stoppingToken)
    {
        if (settings.Disabled || !settings.Enabled("ADLOG_ENABLE_INPROCESS_POST_COLLECTION") || settings.Enabled("ADLOG_EXTERNAL_POST_COLLECTION_WORKER")) return;
        await using var scope = scopes.CreateAsyncScope();
        await using var db = await scope.ServiceProvider.GetRequiredService<IPostgresConnectionFactory>().OpenAsync(stoppingToken);
        await using var acquire = new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_post_collection_process'))",db);
        if (await acquire.ExecuteScalarAsync(stoppingToken) is not true) return;
        try {
            if (settings.Enabled("ADLOG_LEGACY_FINDINGS_ENABLED"))
                await scope.ServiceProvider.GetRequiredService<LegacyFindings>().EnsureAsync(true,stoppingToken);
            string worker = "inprocess-"+Guid.NewGuid().ToString("N")[..12];
            while (!stoppingToken.IsCancellationRequested) {
                if (settings.Disabled || settings.Enabled("ADLOG_EXTERNAL_POST_COLLECTION_WORKER")) return;
                try {
                    var result = await scope.ServiceProvider.GetRequiredService<LegacyPostCollection>().RunOnceAsync(worker,1,stoppingToken);
                    await scope.ServiceProvider.GetRequiredService<LegacyHeartbeat>().WriteAsync("post_collection",worker,result.Failed == 0 ? "idle" : "failed","sleep",30,
                        new() { ["claimed"]=result.Claimed,["completed"]=result.Completed,["failed"]=result.Failed },stoppingToken);
                    if (result.Claimed != 0) continue;
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
                catch { logger.LogWarning("post_collection_iteration_failed"); }
                await Task.Delay(TimeSpan.FromSeconds(30),stoppingToken);
            }
        }
        finally {
            await using var release = new NpgsqlCommand("select pg_advisory_unlock(hashtext('ad_log_reports_runtime_post_collection_process'))",db);
            await release.ExecuteScalarAsync(CancellationToken.None);
        }
    }
}
