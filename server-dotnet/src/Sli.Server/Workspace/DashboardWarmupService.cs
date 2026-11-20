using Sli.Server.Operations;

namespace Sli.Server.Workspace;

// BackgroundService runs off the startup path. Optional cache warmup must not
// delay HTTP startup or make an unavailable component stop the server.
public sealed class DashboardWarmupService(IServiceScopeFactory scopes, OperationsFiles files,
    TimeProvider time, ILogger<DashboardWarmupService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try { _ = files.RuntimeStorage(false, time.GetUtcNow()); }
        catch { logger.LogWarning("system_health_storage_warmup_failed"); }
        try
        {
            await using var scope = scopes.CreateAsyncScope();
            await scope.ServiceProvider.GetRequiredService<DashboardSnapshotReader>().ReadAsync(true, stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        catch { logger.LogWarning("dashboard_snapshot_warmup_failed"); }
    }
}
