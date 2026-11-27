using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Sli.Agent.Windows;

namespace Sli.Agent.Service;

/// <summary>The Windows service loop logs safe diagnostics without packet data.</summary>
public sealed class AgentWorker(AgentRuntime runtime, ILogger<AgentWorker> logger) : BackgroundService
{
    public const string ServiceName = "SLIAgentNet";

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var failures = 0;
        (string? Code, string? Detail) previous = default;
        IReadOnlyDictionary<string, SnapshotFailure>? previousSnapshots = null;
        FileAuditCatalogDiagnostic? previousCatalog = null;
        while (!stoppingToken.IsCancellationRequested)
        {
            CycleStatus status;
            try { status = await runtime.RunCycleAsync(stoppingToken).ConfigureAwait(false); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            failures = status.DeliveryFailed ? Math.Min(failures + 1, 10) : 0;
            var snapshotErrorLoggedSeparately = false;
            if (status.SnapshotFailures is { } snapshots)
            {
                foreach (var (module, failure) in snapshots)
                {
                    if (previousSnapshots?.GetValueOrDefault(module) != failure)
                        logger.LogWarning("agent cycle: {Code}. {Detail}", failure.Code, failure.Detail);
                    snapshotErrorLoggedSeparately |= failure.Code == status.ErrorCode && failure.Detail == status.ErrorDetail;
                }
            }
            previousSnapshots = status.SnapshotFailures;
            if (status.FileAuditCatalog is { } catalog && catalog != previousCatalog)
                logger.LogWarning("File Audit catalog: enumeration {EnumerationError}, Win32 {NativeStatus}, report {ReportError}, HTTP {HttpStatus}",
                    catalog.EnumerationError, catalog.NativeStatus, catalog.ReportError, catalog.HttpStatus);
            previousCatalog = status.FileAuditCatalog;
            if (!snapshotErrorLoggedSeparately)
            {
                if (status.ErrorDetail is not null)
                {
                    if (previous != (status.ErrorCode, status.ErrorDetail))
                        logger.LogWarning("agent cycle: {Code} {Detail}, pending {Pending}, active {Active}",
                            status.ErrorCode, status.ErrorDetail, status.Pending, status.CollectionActive);
                }
                else if (status.ErrorCode is not null)
                    logger.LogWarning("agent cycle: {Code}, pending {Pending}, active {Active}", status.ErrorCode, status.Pending, status.CollectionActive);
                else
                    logger.LogInformation("agent cycle: {Code}, pending {Pending}, active {Active}", "ok", status.Pending, status.CollectionActive);
            }
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
