using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Windows;

namespace Sli.Agent.Service;

/// <summary>Reports one durable audit result at a time without waiting in the event cycle.</summary>
internal sealed class FileAuditReportDelivery(TimeProvider clock) : IDisposable
{
    internal const string Route = "/api/v1/agent/file-audit-report";

    private sealed record Attempt(JsonObject Receipt, CancellationTokenSource Stop, Task<string?> Send)
    {
        internal Task? Cancellation { get; set; }
    }

    private Attempt? _attempt;
    private DateTimeOffset _retryAt;
    internal string? Error { get; private set; }

    internal void Observe(FileAuditManager manager)
    {
        if (_attempt is not { Send.IsCompleted: true } attempt) return;
        _attempt = null;
        Release(attempt);
        if (attempt.Cancellation is not null) return;

        var error = attempt.Send.GetAwaiter().GetResult();
        if (error is null)
        {
            try { manager.Acknowledge(attempt.Receipt); }
            catch (Exception ex) when (ex is AgentException or IOException or UnauthorizedAccessException)
            { error = "file_audit_report_ack_io_failed"; }
        }

        Error = error;
        _retryAt = error is null ? default : clock.GetUtcNow().AddSeconds(5);
    }

    internal void Start(JsonObject report, AgentHttpClient transport, bool readDiagnostics, CancellationToken stopping)
    {
        if (_attempt is not null || clock.GetUtcNow() < _retryAt || stopping.IsCancellationRequested) return;

        var outgoing = report;
        if (!readDiagnostics && report["scopes"] is JsonArray scopes && scopes.OfType<JsonObject>().Any(scope => scope.ContainsKey("read_error")))
        {
            // Keep the durable receipt intact when the server does not support the optional field.
            outgoing = (JsonObject)report.DeepClone();
            foreach (var scope in outgoing["scopes"]!.AsArray().OfType<JsonObject>())
                scope.Remove("read_error");
        }

        var stop = CancellationTokenSource.CreateLinkedTokenSource(stopping);
        stop.CancelAfter(TimeSpan.FromSeconds(15));
        var ct = stop.Token;
        _attempt = new(report, stop, Task.Run(() => SendAsync(transport, outgoing, ct)));
    }

    private static async Task<string?> SendAsync(AgentHttpClient transport, JsonObject report, CancellationToken ct)
    {
        try
        {
            var reply = await transport.PostAsync(Route, report, ct).ConfigureAwait(false);
            return reply["status"]?.ToString() == "accepted" ? null : "file_audit_report_ack_invalid";
        }
        catch (TransportException ex) { return ex.Code; }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { return "file_audit_report_timeout"; }
        catch (Exception) { return "file_audit_report_failed"; }
    }

    internal void Cancel()
    {
        if (_attempt is { Cancellation: null } attempt) attempt.Cancellation = attempt.Stop.CancelAsync();
    }

    public void Dispose()
    {
        Cancel();
        if (_attempt is not { } attempt) return;
        _attempt = null;
        _ = attempt.Send.ContinueWith(_ => Release(attempt), TaskScheduler.Default);
    }

    private static void Release(Attempt attempt)
    {
        if (attempt.Cancellation is not { } cancellation)
        {
            attempt.Stop.Dispose();
            return;
        }

        _ = cancellation.ContinueWith(task =>
        {
            _ = task.Exception;
            attempt.Stop.Dispose();
        }, TaskScheduler.Default);
    }
}
