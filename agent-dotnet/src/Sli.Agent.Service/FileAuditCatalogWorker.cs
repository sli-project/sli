using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Windows;

namespace Sli.Agent.Service;

public sealed record FileAuditCatalogDiagnostic(string? EnumerationError, uint? NativeStatus, string? ReportError, int? HttpStatus);

/// <summary>One optional catalog job, with no wait or queue writes in the event collection cycle.</summary>
internal sealed class FileAuditCatalogWorker(Func<CancellationToken, LocalSmbCatalog> read, TimeProvider clock) : IDisposable
{
    internal const string ReportPath = "/api/v1/agent/file-audit-catalog-report";

    private sealed record Offer(Guid Id, DateTimeOffset Expires);
    private sealed record Prepared(JsonObject Body, string? EnumerationError, uint? NativeStatus);
    private sealed record Outcome(Prepared? Report, bool Retry, string? Error = null, int? HttpStatus = null);
    private sealed record Job(Guid Id, CancellationTokenSource Stop, Task<Outcome> Task)
    {
        internal Task? Cancellation { get; set; }
        internal bool Discard => Cancellation is not null;
    }

    private Job? _job;
    private Guid? _request;
    private Prepared? _pending;
    private bool _done;
    private int _attempts;
    private DateTimeOffset _retryAt;
    internal FileAuditCatalogDiagnostic? Diagnostic { get; private set; }

    internal void Tick(JsonNode? value, AgentHttpClient transport, bool readDiagnostics, CancellationToken stopping)
    {
        var now = clock.GetUtcNow();
        var offer = ParseOffer(value, now);
        Observe(now);
        if (_request != offer?.Id)
        {
            Cancel();
            _request = offer?.Id;
            _pending = null;
            _done = false;
            _attempts = 0;
            _retryAt = default;
            if (offer is not null) Diagnostic = null;
        }
        if (_job is not null || offer is null || _done || _attempts >= 3 || now < _retryAt || stopping.IsCancellationRequested)
            return;

        var stop = CancellationTokenSource.CreateLinkedTokenSource(stopping);
        var remaining = offer.Expires - now;
        stop.CancelAfter(remaining < TimeSpan.FromSeconds(15) ? remaining : TimeSpan.FromSeconds(15));
        var pending = _pending;
        var cancellationToken = stop.Token;
        _attempts++;
        _job = new(offer.Id, stop, Task.Run(() => RunAsync(offer.Id, pending, transport, readDiagnostics, cancellationToken)));
    }

    private void Observe(DateTimeOffset now)
    {
        if (_job is not { } job || !job.Task.IsCompleted) return;
        _job = null;
        Release(job);
        if (job.Discard || job.Id != _request)
        {
            _ = job.Task.Exception;
            return;
        }

        var outcome = job.Task.IsCompletedSuccessfully ? job.Task.Result : new Outcome(null, true, "file_audit_catalog_worker_failed");
        _ = job.Task.Exception;
        _pending = outcome.Report;
        _done = !outcome.Retry;
        _retryAt = now.AddSeconds(5);
        Diagnostic = outcome.Report?.EnumerationError is null && outcome.Error is null ? null : new(
            outcome.Report?.EnumerationError, outcome.Report?.NativeStatus, outcome.Error, outcome.HttpStatus);
    }

    private async Task<Outcome> RunAsync(Guid request, Prepared? report, AgentHttpClient transport, bool readDiagnostics, CancellationToken ct)
    {
        try
        {
            report ??= Prepare(request, ct);
            ct.ThrowIfCancellationRequested();
            var outgoing = report.Body;
            if (readDiagnostics && report.NativeStatus is uint status && status != 0)
            {
                outgoing = (JsonObject)report.Body.DeepClone();
                outgoing["native_status"] = status;
            }
            var response = await transport.PostAsync(ReportPath, outgoing, ct).ConfigureAwait(false);
            return response["status"]?.ToString() == "accepted"
                ? new(report, false)
                : new(report, true, "file_audit_catalog_ack_invalid");
        }
        catch (TransportException e)
        {
            bool retry = e.HttpStatus is null or 408 or 429 or >= 500;
            return new(report, retry, e.Code, e.HttpStatus);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return report is null
                ? new(Unavailable(request, "file_audit_catalog_enumeration_timeout"), true)
                : new(report, true, "file_audit_catalog_report_timeout");
        }
        catch (Exception)
        {
            return report is null
                ? new(Unavailable(request, "file_audit_catalog_enumeration_failed"), true)
                : new(report, true, "file_audit_catalog_report_failed");
        }
    }

    private Prepared Prepare(Guid request, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var result = read(ct);
        ct.ThrowIfCancellationRequested();
        if (result.State == LocalSmbCatalogState.Unavailable)
            return Unavailable(request, "file_audit_catalog_enumeration_failed", result.NativeStatus);
        if (result.State == LocalSmbCatalogState.Incomplete || result.Shares.Count > 128)
            return new(NewBody(request, "incomplete"), "file_audit_catalog_incomplete", result.NativeStatus);

        var body = NewBody(request, "ready", new JsonArray(result.Shares.Select(share => (JsonNode?)new JsonObject
        {
            ["share_name"] = share.Name, ["path"] = share.Path
        }).ToArray()));
        return CanonicalJson.Length(body) <= 65536
            ? new(body, null, null)
            : new(NewBody(request, "incomplete"), "file_audit_catalog_size_limit", null);
    }

    private static Prepared Unavailable(Guid request, string code, uint? status = null) =>
        new(NewBody(request, "unavailable"), code, status);

    private static JsonObject NewBody(Guid request, string status, JsonArray? shares = null) => new()
    {
        ["request_id"] = request.ToString("D"), ["status"] = status, ["shares"] = shares ?? new JsonArray()
    };

    private static Offer? ParseOffer(JsonNode? value, DateTimeOffset now)
    {
        if (value is not JsonObject body || !JsonRead.HasExactly(body, "request_id", "expires_at")
            || !JsonRead.TryString(body["request_id"], out var id) || !Guid.TryParseExact(id, "D", out var request)
            || request == Guid.Empty || !JsonRead.TryString(body["expires_at"], out var expiry)
            || !Iso8601.TryParseUtc(expiry, out var expires) || expires <= now)
            return null;
        return new(request, expires);
    }

    internal void Cancel()
    {
        if (_job is not { Discard: false } job) return;
        job.Cancellation = job.Stop.CancelAsync();
    }

    public void Dispose()
    {
        Cancel();
        if (_job is not { } job) return;
        _job = null;
        _ = job.Task.ContinueWith(task =>
        {
            _ = task.Exception;
            Release(job);
        }, TaskScheduler.Default);
    }

    private static void Release(Job job)
    {
        if (job.Cancellation is not { } cancellation)
        {
            job.Stop.Dispose();
            return;
        }
        _ = cancellation.ContinueWith(task =>
        {
            _ = task.Exception;
            job.Stop.Dispose();
        }, TaskScheduler.Default);
    }
}
