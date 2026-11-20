using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Core;
using Sli.Agent.Protocol;

namespace Sli.Server.Agents.Radius;

// Remote collector contract from collect_windows_events.py; the local agent
// bookmark reader deliberately has a different (unfiltered) source contract.
internal sealed record NpsEventLogRequest(string ComputerName, string SourceName, string StartTimeUtc, string EndTimeUtc)
{
    public bool NpsContinuous { get; init; }
    public string CredentialMode { get; init; } = "process";
    public string[] Channels { get; init; } = ["Security"];
    public int[] EventIds { get; init; } = [6272, 6273];
    public bool CollectMessage { get; init; }
    public int MaxEvents { get; init; } = 50_000;
    public int ChannelTimeoutSeconds { get; init; } = 60;
    public Dictionary<string, int> ChannelLimits { get; init; } = [];
    public Dictionary<string, int> ChannelTimeouts { get; init; } = [];
    public Dictionary<string, string> ChannelStarts { get; init; } = [];
    public Dictionary<string, long> AfterRecordIds { get; init; } = [];
    public Dictionary<string, string> CursorGenerations { get; init; } = [];

    internal void Validate()
    {
        var start = NpsEventLogTransport.Utc(StartTimeUtc);
        var end = NpsEventLogTransport.Utc(EndTimeUtc);
        if (end <= start) throw new ArgumentException("continuous_nps_time_window_invalid");
        if (!NpsContinuous) return;
        static void Require(bool condition, string code) { if (!condition) throw new ArgumentException(code); }
        Require(Channels.SequenceEqual(["Security"]), "continuous_nps_security_channel_required");
        Require(EventIds.Order().Distinct().SequenceEqual([6272, 6273]), "continuous_nps_event_ids_mismatch");
        Require(CredentialMode == "dpapi_current_user", "continuous_nps_dpapi_required");
        Require(!CollectMessage, "continuous_nps_message_collection_forbidden");
        Require(AfterRecordIds.Keys.Concat(CursorGenerations.Keys).All(x => x == "Security"), "continuous_nps_cursor_channels_invalid");
        Require(ChannelLimits.Keys.Concat(ChannelTimeouts.Keys).Concat(ChannelStarts.Keys).All(x => x == "Security"), "continuous_nps_channel_overrides_invalid");
        Require((AfterRecordIds.Count == 0) == (CursorGenerations.Count == 0), "continuous_nps_cursor_generation_pair_required");
        Require(AfterRecordIds.Values.All(x => x >= 1), "continuous_nps_record_id_invalid");
        Require(CursorGenerations.Values.All(x => !string.IsNullOrWhiteSpace(x)), "continuous_nps_generation_invalid");
        // Compatibility admission only. These are never execution deadlines or
        // truncation limits: the frozen selector is read to exhaustion.
        Require(MaxEvents is >= 1 and <= 50_000, "continuous_nps_global_event_limit_invalid");
        Require(ChannelTimeoutSeconds is >= 1 and <= 60, "continuous_nps_global_channel_timeout_invalid");
        Require(ChannelLimits.Values.All(x => x >= 1 && x <= MaxEvents), "continuous_nps_effective_event_limit_invalid");
        Require(ChannelTimeouts.Values.All(x => x >= 1 && x <= ChannelTimeoutSeconds), "continuous_nps_effective_channel_timeout_invalid");
        Require(ChannelStarts.Values.All(x => NpsEventLogTransport.Utc(x) >= start && NpsEventLogTransport.Utc(x) <= end), "continuous_nps_channel_start_out_of_range");
    }
}

internal sealed record NpsChannelState(long? LatestRecordId, long? OldestRecordId, string Generation);
internal sealed class NpsEventLogException(string code) : Exception(code);
internal interface INpsRemoteSession : IDisposable
{
    NpsChannelState Probe(string channel, Action heartbeat, CancellationToken ct);
    IEnumerable<string> Read(string channel, string xpath, Action heartbeat, CancellationToken ct);
}

internal static class NpsEventLogTransport
{
    internal const string Provider = "Microsoft-Windows-Security-Auditing";
    internal static DateTimeOffset Utc(string text)
    {
        if (!Iso8601.TryParseUtc(text, out var value)) throw new ArgumentException("bounded_selection_event_time_invalid");
        return value;
    }

    internal static string ResolveEndpoint(NpsEventLogRequest request, JsonObject route)
    {
        string Text(string key) => (route[key]?.GetValue<string>() ?? "").Trim();
        static bool Fqdn(string value) => value.Length <= 253 && Regex.IsMatch(value,
            @"\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\z", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        string name = Text("source_name");
        if (!Fqdn(name) || !name.Equals(Text("source_instance_id"), StringComparison.OrdinalIgnoreCase)
            || Text("owner_confirmed_ip").Length == 0 || route["event_log_ready"]?.GetValue<bool>() != true
            || Text("event_log_adapter") != "windows-eventlog-pywin32")
            throw new InvalidOperationException("nps_eventlog_registered_route_required");
        if (!Fqdn(request.SourceName.Trim()) || !Fqdn(request.ComputerName.Trim())
            || !name.Equals(request.SourceName.Trim(), StringComparison.OrdinalIgnoreCase)
            || !name.Equals(request.ComputerName.Trim(), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("nps_eventlog_endpoint_invalid");
        return name;
    }

    internal static INpsRemoteSession OpenSession(NpsEventLogRequest request, Func<JsonObject> routeLoader,
        Func<string, NpsSourceCredentials> loadCredentials, Func<string, NpsSourceCredentials?, INpsRemoteSession> open)
    {
        request.Validate();
        if (!request.NpsContinuous)
        {
            if (request.CredentialMode != "process") throw new InvalidOperationException("ad_source_endpoint_invalid");
            return open(request.ComputerName, null);
        }
        // Endpoint admission MUST precede both credential loading and RPC.
        string target = ResolveEndpoint(request, routeLoader());
        NpsSourceCredentials credentials;
        try { credentials = loadCredentials("vpn"); }
        catch { throw new NpsEventLogException("ad_source_credentials_unavailable"); }
        try { return open(target, credentials); }
        catch (Exception e) { throw new NpsEventLogException(PublicError(e)); }
    }

    internal static string XPath(NpsEventLogRequest r, string start, long? after, long? through)
    {
        var predicates = new List<string>();
        var ids = r.EventIds.Order().Distinct().ToArray();
        if (ids.Length > 0) predicates.Add(ids.Length == 1 ? $"EventID={ids[0]}" : "(" + string.Join(" or ", ids.Select(x => $"EventID={x}")) + ")");
        if (r.NpsContinuous) predicates.Add($"Provider[@Name='{Provider}']");
        if (after is not null) predicates.Add($"EventRecordID > {after.Value.ToString(CultureInfo.InvariantCulture)}");
        else predicates.Add($"TimeCreated[@SystemTime >= '{Utc(start):yyyy-MM-ddTHH:mm:ss.ffffffZ}' and @SystemTime <= '{Utc(r.EndTimeUtc):yyyy-MM-ddTHH:mm:ss.ffffffZ}']");
        if (through is not null) predicates.Add($"EventRecordID <= {through.Value.ToString(CultureInfo.InvariantCulture)}");
        return "*[System[" + string.Join(" and ", predicates) + "]]";
    }

    internal static void ValidateRow(JsonObject row, NpsEventLogRequest r, string start)
    {
        if (!r.EventIds.Contains(row["event_id"]?.GetValue<int>() ?? 0)) throw new InvalidDataException("bounded_selection_event_id_mismatch");
        if (r.NpsContinuous && row["provider_name"]?.GetValue<string>() != Provider) throw new InvalidDataException("bounded_selection_provider_mismatch");
        var stamp = Utc(row["time_created"]?.GetValue<string>() ?? "");
        if (stamp < Utc(start) || stamp > Utc(r.EndTimeUtc)) throw new InvalidDataException("bounded_selection_event_time_out_of_range");
    }

    internal static string PublicError(Exception error)
    {
        if (error is NpsEventLogException safe) return safe.Message;
        if (error is System.ComponentModel.Win32Exception native)
        {
            int code = native.NativeErrorCode & 0xffff;
            return (code == 5 ? "windows_event_log_access_denied" : "ad_source_rpc_failed") + $" winerror {code}";
        }
        return "ad_source_rpc_failed";
    }

    internal static JsonObject Collect(NpsEventLogRequest r, string channel, TextWriter output,
        Func<INpsRemoteSession> open, Action<string>? logError = null, Action<JsonObject>? heartbeat = null, CancellationToken ct = default)
    {
        r.Validate(); // No file, credentials or source side effects before admission.
        string start = r.ChannelStarts.GetValueOrDefault(channel, r.StartTimeUtc);
        long? after = r.AfterRecordIds.TryGetValue(channel, out long saved) ? saved : null;
        long? effective = after, latest = null;
        NpsChannelState? before = null, post = null;
        int count = 0;
        string? error = null, fallback = null;
        bool exhausted = false;
        string stage = "open_remote_session";
        void Beat() => heartbeat?.Invoke(new JsonObject { ["stage"] = stage, ["count"] = count, ["latest_record_id"] = latest });
        Beat();
        try
        {
            using var session = open();
            if (r.NpsContinuous || after is not null)
            {
                stage = "probe_channel"; Beat();
                before = session.Probe(channel, Beat, ct);
                if (after is not null)
                {
                    if (before.LatestRecordId < after) fallback = "latest_record_id_before_saved_cursor";
                    else if (!r.CursorGenerations.TryGetValue(channel, out var generation) || string.IsNullOrEmpty(before.Generation)) fallback = "channel_generation_missing";
                    else if (generation != before.Generation) fallback = "channel_generation_changed";
                    else if (before.OldestRecordId > after + 1) fallback = "oldest_record_id_after_saved_cursor";
                    if (fallback is not null) effective = null;
                }
            }
            stage = "read"; Beat();
            foreach (string xml in session.Read(channel, XPath(r, start, effective, before?.LatestRecordId), Beat, ct))
            {
                ct.ThrowIfCancellationRequested();
                var row = EventXml.Parse(xml, r.SourceName, r.ComputerName, channel);
                ValidateRow(row, r, start); // Validate rendered evidence, never trust the query alone.
                long? id = row["record_id"]?.GetValue<long>();
                var packet = CollectionPacket.Make(r.SourceName, channel, before?.Generation,
                    new JsonObject { ["after_record_id"] = effective, ["last_record_id"] = id },
                    [new PacketRecord("event_xml", id, row)], "not_proven", null, DateTimeOffset.UtcNow);
                output.WriteLine(packet.ToJsonString());
                count++;
                if (id is not null) latest = latest is null ? id : Math.Max(latest.Value, id.Value);
                Beat();
            }
            exhausted = true;
            if (before is not null) { stage = "probe_after_read"; Beat(); post = session.Probe(channel, Beat, ct); }
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            error = r.CredentialMode == "process" ? e is InvalidDataException ? e.Message : PublicError(e) : PublicError(e);
            logError?.Invoke(error); // Only the sanitized public error crosses the boundary.
        }
        output.Flush();
        stage = "finished"; Beat();
        bool stable = before is not null && before.Generation == post?.Generation;
        bool complete = error is null && exhausted && after is not null && fallback is null && stable && before?.LatestRecordId is not null;
        return new JsonObject {
            ["channel"] = channel, ["status"] = error is null ? "completed" : count == 0 ? "failed" : "partial_timeout",
            ["count"] = count, ["error"] = error, ["after_record_id"] = after, ["effective_after_record_id"] = effective,
            ["saved_channel_generation_identity"] = r.CursorGenerations.GetValueOrDefault(channel),
            ["channel_generation_identity"] = before?.Generation, ["channel_generation_identity_after_read"] = post?.Generation,
            ["channel_latest_record_id_before_read"] = before?.LatestRecordId, ["batch_max_record_id"] = latest,
            ["start_time_utc"] = start, ["end_time_utc"] = r.EndTimeUtc, ["latest_available_record_id"] = latest,
            ["cursor_strategy"] = after is null ? "time_window" : fallback is null ? "record_id" : "time_window_fallback",
            ["cursor_fallback_reason"] = fallback,
            ["cursor_commit_allowed"] = error is null && exhausted && stable && fallback is null,
            ["continuity"] = new JsonObject {
                ["contract"] = "sli.source-capture-continuity.v1", ["status"] = complete ? "complete" : "not_proven",
                ["after_record_id"] = after, ["latest_record_id"] = before?.LatestRecordId,
                ["channel_generation_identity"] = before?.Generation, ["channel_generation_identity_after_read"] = post?.Generation,
                ["generation_stable_during_read"] = stable, ["oldest_record_id"] = before?.OldestRecordId,
                ["truncated"] = false, ["selector_event_ids"] = new JsonArray(r.EventIds.Order().Distinct().Select(x => (JsonNode?)JsonValue.Create(x)).ToArray()),
                ["query_exhausted"] = exhausted,
            },
        };
    }
}
