using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sli.Agent.Service;

/// <summary>The Windows service loop logs safe diagnostics without packet data.</summary>
public sealed class AgentWorker(AgentRuntime runtime, ILogger<AgentWorker> logger) : BackgroundService
{
    public const string ServiceName = "SLIAgentNet";

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var failures = 0;
        (string? Code, string? Detail) previous = default;
        while (!stoppingToken.IsCancellationRequested)
        {
            CycleStatus status;
            try { status = await runtime.RunCycleAsync(stoppingToken).ConfigureAwait(false); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            failures = status.DeliveryFailed ? Math.Min(failures + 1, 10) : 0;
            if (status.ErrorDetail is not null)
            {
                if (previous != (status.ErrorCode, status.ErrorDetail))
                    logger.LogWarning("agent cycle: {Code}, pending {Pending}, active {Active}. {Detail}",
                        status.ErrorCode, status.Pending, status.CollectionActive, status.ErrorDetail);
            }
            else if (status.ErrorCode is not null)
                logger.LogWarning("agent cycle: {Code}, pending {Pending}, active {Active}", status.ErrorCode, status.Pending, status.CollectionActive);
            else
                logger.LogInformation("agent cycle: {Code}, pending {Pending}, active {Active}", "ok", status.Pending, status.CollectionActive);
            previous = (status.ErrorCode, status.ErrorDetail);
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
