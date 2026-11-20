using System.Text.Json.Nodes;
using Sli.Server.Agents.Registry;

namespace Sli.Server.Agents.WindowsEventLog;

public sealed record WindowsEventLogOptions
{
    public string? EventIdsJson { get; init; }
    public string? StartTimeUtc { get; init; }
    public string? EndTimeUtc { get; init; }
    public string Backend { get; init; } = "python";
    public string Server { get; init; } = "";
    public string ConnectAddress { get; init; } = "";
    public string[] Channels { get; init; } = ["Security"];
    public bool Archive { get; init; }
    public bool UseRecordIdCursor { get; init; }
    public string AdaptiveStateMode { get; init; } = "observe";
    public bool CollectMessage { get; init; }
    public int MaxEventsPerChannel { get; init; } = 500;
    public int ChannelTimeoutSeconds { get; init; } = 30;
    public int CommandTimeoutSeconds { get; init; } = 60;
    public bool SourceContinuityCanary { get; init; }
    public Dictionary<string, long> AfterRecordIds { get; init; } = [];
    public Dictionary<string, string> CursorGenerations { get; init; } = [];
    public Dictionary<string, int> ChannelLimits { get; init; } = [];
    public Dictionary<string, int> ChannelTimeouts { get; init; } = [];
}

public static class WindowsEventLogAdmission
{
    private static readonly int[] AuthenticationEventIds = [4608, 4624, 4634, 4672];
    private static void Require(bool condition, string code) { if (!condition) throw new ArgumentException(code); }
    public static WindowsEventLogSelection? Nps(WindowsEventLogOptions request, Func<JsonObject> routeLoader)
    {
        var selection = WindowsEventLogSelection.Parse(request.EventIdsJson, request.StartTimeUtc, request.EndTimeUtc);
        if (selection is null) return null;
        Require(selection.EventIds.SequenceEqual([6272]), "bounded_nps_event_ids_mismatch");
        Runtime(request, "bounded_nps");
        Require(!request.Archive && !request.UseRecordIdCursor && request.AdaptiveStateMode == "observe", "bounded_nps_runtime_state_mutation_forbidden");
        // These are the frozen diagnostic request contract, not execution deadlines.
        Bounds(request, "bounded_nps", 500, 60, 75);
        var route = routeLoader();
        string Text(string key) => route[key] is JsonValue value && value.TryGetValue<string>(out var s) ? s : "";
        string source = Text("source_name").Trim();
        Require(source.Length > 0 && Text("source_instance_id").Trim().Length > 0 &&
            route["event_log_ready"] is JsonValue ready && ready.TryGetValue<bool>(out var enabled) && enabled &&
            Text("event_log_adapter") == "windows-eventlog-pywin32", "bounded_nps_registered_route_required");
        Require(UnicodeCaseFold.Fold(request.Server) == UnicodeCaseFold.Fold(source), "bounded_nps_server_mismatch");
        Require(UnicodeCaseFold.Fold(request.ConnectAddress) == UnicodeCaseFold.Fold(source), "bounded_nps_connect_address_mismatch");
        return selection;
    }

    public static WindowsEventLogSelection Canary(WindowsEventLogOptions request)
    {
        var selection = WindowsEventLogSelection.Parse(request.EventIdsJson, request.StartTimeUtc, request.EndTimeUtc)
            ?? throw new ArgumentException("source_continuity_canary_selection_missing");
        Require(selection.EventIds.SequenceEqual(AuthenticationEventIds), "source_continuity_canary_event_ids_mismatch");
        Runtime(request, "source_continuity_canary");
        Require(request.Archive && request.UseRecordIdCursor, "source_continuity_canary_record_cursor_required");
        Require(request.AdaptiveStateMode == "update", "source_continuity_canary_adaptive_update_required");
        Bounds(request, "source_continuity_canary", 5000, 120, 180);
        return selection;
    }

    private static void Runtime(WindowsEventLogOptions request, string prefix)
    {
        Require(request.Backend == "python", prefix + "_python_backend_required");
        Require(request.Channels.SequenceEqual(["Security"]), prefix + "_security_channel_required");
        Require(!request.CollectMessage, prefix + "_message_collection_forbidden");
    }

    private static void Bounds(WindowsEventLogOptions request, string prefix, int events, int channel, int command)
    {
        Require(request.MaxEventsPerChannel >= 1 && request.MaxEventsPerChannel <= events, prefix + "_event_limit_invalid");
        Require(request.ChannelTimeoutSeconds >= 1 && request.ChannelTimeoutSeconds <= channel, prefix + "_channel_timeout_invalid");
        Require(request.CommandTimeoutSeconds >= 1 && request.CommandTimeoutSeconds <= command, prefix + "_command_timeout_invalid");
    }

    public static void CollectorCursor(WindowsEventLogOptions request, WindowsEventLogSelection? selection)
    {
        if (!request.SourceContinuityCanary)
        {
            Require(selection is null || request.AfterRecordIds.Count == 0, "record-id cursor is forbidden");
            return;
        }
        Require(selection is not null, "source-continuity canary requires a bounded selection");
        Require(selection!.EventIds.SequenceEqual(AuthenticationEventIds), "source-continuity canary Event ID selector mismatch");
        Require(request.Channels.SequenceEqual(["Security"]), "source-continuity canary requires only the Security channel");
        Require(request.AfterRecordIds.Count == 1 && request.AfterRecordIds.TryGetValue("Security", out long id) && id > 0,
            "source-continuity canary requires a saved Security record-id cursor");
        Require(request.CursorGenerations.TryGetValue("Security", out var generation) && !string.IsNullOrWhiteSpace(generation),
            "source-continuity canary requires a saved Security generation");
        Require(!request.CollectMessage, "source-continuity canary forbids message collection");
        Require(request.ChannelLimits.GetValueOrDefault("Security", request.MaxEventsPerChannel) is >= 1 and <= 5000,
            "source-continuity canary event limit is invalid");
        Require(request.ChannelTimeouts.GetValueOrDefault("Security", request.ChannelTimeoutSeconds) is >= 1 and <= 120,
            "source-continuity canary channel timeout is invalid");
    }
}
