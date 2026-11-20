using System.Text.Json.Nodes;
using Sli.Agent.Core;

namespace Sli.Server.Agents.WindowsEventLog;

public sealed record WindowsEventLogRead(string ComputerName, string Channel, string XPath, long? AfterRecordId, string? SavedGeneration);
public sealed record WindowsEventLogCollectionResult(int ExitCode, string Status, int Count, string? Error = null);

// The native reader is the same IDisposable/read boundary as the existing NPS source.
// Admission completes before opening it; validation precedes every JSONL write.
public static class BoundedWindowsEventLogCollector
{
    public static WindowsEventLogCollectionResult RunNps(WindowsEventLogOptions request, Func<JsonObject> routeLoader,
        Func<WindowsEventLogRead, INpsEventLogReader> open, TextWriter output, CancellationToken ct = default)
    {
        try { WindowsEventLogAdmission.Nps(request, routeLoader); }
        catch (Exception e) when (e is not OperationCanceledException)
        { return new(64, "failed", 0, e is ArgumentException ? e.Message : "bounded_nps_registered_route_required"); }
        return Collect(request, open, output, ct);
    }

    public static WindowsEventLogCollectionResult Collect(WindowsEventLogOptions request,
        Func<WindowsEventLogRead, INpsEventLogReader> open, TextWriter output, CancellationToken ct = default,
        Action<int>? progress = null)
    {
        WindowsEventLogSelection selection;
        try
        {
            selection = WindowsEventLogSelection.Parse(request.EventIdsJson, request.StartTimeUtc, request.EndTimeUtc)
                ?? throw new ArgumentException("bounded selection required");
            WindowsEventLogAdmission.CollectorCursor(request, selection);
        }
        catch (ArgumentException e) { return new(12, "failed", 0, e.Message); }
        int count = 0;
        try
        {
            foreach (var channel in request.Channels)
            {
                ct.ThrowIfCancellationRequested();
                long? after = request.AfterRecordIds.TryGetValue(channel, out var record) ? record : null;
                using var reader = open(new(request.ConnectAddress, channel, selection.BuildXPath(after), after,
                    request.CursorGenerations.GetValueOrDefault(channel)));
                while (true)
                {
                    ct.ThrowIfCancellationRequested();
                    var item = reader.Read();
                    if (item is null) break;
                    var row = EventXml.Parse(item.Xml, request.Server, request.ConnectAddress, channel);
                    selection.ValidateRow(row);
                    output.WriteLine(row.ToJsonString());
                    count++;
                    progress?.Invoke(count);
                }
            }
            return new(0, "completed", count);
        }
        catch (InvalidOperationException e) when (e.Message.StartsWith("bounded_selection_", StringComparison.Ordinal))
        { return new(1, "failed", count, e.Message); }
        catch (Exception e) when (e is not OperationCanceledException)
        { return new(1, "failed", count, "windows_eventlog_collection_failed"); }
    }
}
