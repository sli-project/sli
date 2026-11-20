using System.Globalization;
using System.Text.Json;

namespace Sli.Server.Agents.WindowsEventLog;

public sealed record WindowsEventLogCommandRequest(WindowsEventLogOptions Options)
{
    public string PythonExecutable { get; init; } = "python";
    public string PythonScript { get; init; } = "scripts/collect/collect_windows_events.py";
    public string PowerShellScript { get; init; } = "scripts/collect/Collect-DcEventsLastHour.ps1";
    public string OutputRoot { get; init; } = "raw";
    public int Hours { get; init; } = 1;
    public string CollectionMode { get; init; } = "current";
    public Dictionary<string, string> ChannelStartTimes { get; init; } = [];
}

// Acquisition command contracts only. Arguments are separate tokens, never a shell string.
public static class WindowsEventLogAdapter
{
    public static string[] BuildCommand(WindowsEventLogCommandRequest request)
    {
        var o = request.Options;
        string? ids = null;
        if (o.EventIdsJson is not null)
        {
            using var document = JsonDocument.Parse(o.EventIdsJson);
            if (document.RootElement.ValueKind != JsonValueKind.Array) throw new ArgumentException("event ID allowlist must be an array");
            if (document.RootElement.GetArrayLength() > 0) ids = JsonSerializer.Serialize(document.RootElement);
        }
        var command = new List<string>();
        string Number(int n) => n.ToString(CultureInfo.InvariantCulture);
        void Pair(string name, string value) { command.Add(name); command.Add(value); }
        void Map<T>(string name, Dictionary<string, T> map) { if (map.Count > 0) Pair(name, JsonSerializer.Serialize(map)); }
        if (o.Backend == "python")
        {
            command.Add(request.PythonExecutable); command.Add(request.PythonScript);
            Pair("--computer-name", o.ConnectAddress); Pair("--source-name", o.Server);
            Pair("--hours", Number(request.Hours)); Pair("--max-events-per-channel", Number(o.MaxEventsPerChannel));
            Pair("--channel-timeout-seconds", Number(o.ChannelTimeoutSeconds)); Pair("--output-root", request.OutputRoot);
            Pair("--channels", string.Join(',', o.Channels)); Pair("--collection-mode", request.CollectionMode);
            Pair("--collect-message", o.CollectMessage ? "true" : "false");
            Map("--channel-limits-json", o.ChannelLimits); Map("--channel-timeouts-json", o.ChannelTimeouts);
            if (o.StartTimeUtc is { Length: > 0 } start) Pair("--start-time-utc", start);
            if (ids is not null) Pair("--event-ids-json", ids);
            if (o.EndTimeUtc is { Length: > 0 } end) Pair("--end-time-utc", end);
            if (o.SourceContinuityCanary) command.Add("--source-continuity-canary");
            Map("--channel-start-times-json", request.ChannelStartTimes);
            Map("--channel-after-record-ids-json", o.AfterRecordIds); Map("--channel-cursor-generations-json", o.CursorGenerations);
        }
        else
        {
            if (ids is not null || !string.IsNullOrEmpty(o.EndTimeUtc) || o.SourceContinuityCanary)
                throw new ArgumentException("bounded Windows Event Log selection requires the python backend");
            if (o.Backend != "powershell") throw new ArgumentException("unsupported Windows Event Log backend");
            command.AddRange(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", request.PowerShellScript]);
            Pair("-ComputerName", o.ConnectAddress); Pair("-SourceName", o.Server); Pair("-Hours", Number(request.Hours));
            Pair("-MaxEventsPerChannel", Number(o.MaxEventsPerChannel)); Pair("-ChannelTimeoutSeconds", Number(o.ChannelTimeoutSeconds));
            Pair("-OutputRoot", request.OutputRoot); command.Add(o.CollectMessage ? "-CollectMessage:$true" : "-CollectMessage:$false");
            Pair("-RequestedCollectionMode", request.CollectionMode);
            if (o.Channels.Length > 0) Pair("-Channels", string.Join(',', o.Channels));
            Map("-ChannelMaxEventsJson", o.ChannelLimits); Map("-ChannelTimeoutSecondsJson", o.ChannelTimeouts);
            if (o.StartTimeUtc is { Length: > 0 } start) Pair("-StartTimeUtc", start);
            Map("-ChannelStartTimesJson", request.ChannelStartTimes); Map("-ChannelAfterRecordIdsJson", o.AfterRecordIds);
        }
        return command.ToArray();
    }
}
