using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sli.Agent.Service;

/// <summary>The long-running loop of the Windows service. Logs carry codes only, never packet data.</summary>
public sealed class AgentWorker(AgentRuntime runtime, ILogger<AgentWorker> logger) : BackgroundService
{
    public const string ServiceName = "SLIAgentNet";

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var failures = 0;
        while (!stoppingToken.IsCancellationRequested)
        {
            CycleStatus status;
            try { status = await runtime.RunCycleAsync(stoppingToken).ConfigureAwait(false); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            failures = status.DeliveryFailed ? Math.Min(failures + 1, 10) : 0;
            if (status.ErrorCode is not null)
                logger.LogWarning("agent cycle: {Code}, pending {Pending}, active {Active}", status.ErrorCode, status.Pending, status.CollectionActive);
            else
                logger.LogInformation("agent cycle: {Code}, pending {Pending}, active {Active}", "ok", status.Pending, status.CollectionActive);
            if (runtime.ContinueImmediately) continue;
            try
            {
                await Task.Delay(Backoff.Delay(runtime.IntervalSeconds, failures, errorCode: status.ErrorCode), stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }
}
