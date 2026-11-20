using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;

namespace Sli.Server.Legacy;

// Portable part of collect_windows_events / postgres_runtime_pipeline. Native
// Event Log handles and publication admission remain with their existing owners.
internal static class CollectorCursorContract
{
    internal static JsonObject ChannelState(string channel, string creationTime, long? latest, long? oldest)
    {
        var payload = new JsonObject { ["channel"] = channel, ["creation_time"] = creationTime };
        string digest = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(CanonicalJson.ToBytes(payload)));
        return new() { ["latest_record_id"] = latest, ["oldest_record_id"] = oldest,
            ["generation_identity"] = "sli.windows-event-channel-generation.v1:" + digest };
    }
    internal static (string Strategy, long? After, string? Reason) Resolve(long? saved, long? latest)
        => saved is null ? ("time_window", null, null)
        : latest < saved ? ("time_window_fallback", null, "latest_record_id_before_saved_cursor")
        : ("record_id", saved, null);

    internal static (string Strategy, long? After, string? Reason) ResolveChannel(long? saved, long? latest,
        long? oldest, string? savedGeneration, string? generation)
    {
        var result = Resolve(saved, latest);
        if (saved is null || result.Reason is not null) return result;
        string? reason = string.IsNullOrEmpty(savedGeneration) || string.IsNullOrEmpty(generation) ? "channel_generation_missing"
            : savedGeneration != generation ? "channel_generation_changed"
            : oldest is {} first && saved < long.MaxValue && first > saved + 1 ? "oldest_record_id_after_saved_cursor" : null;
        return reason is null ? result : ("time_window_fallback", null, reason);
    }

    internal static string XPath(long? after, string? start, long? through = null, IEnumerable<int>? eventIds = null)
    {
        var predicates = new List<string>();
        var ids = (eventIds ?? []).Distinct().Order().ToArray();
        if (ids.Any(id => id <= 0)) throw new ArgumentException("selector_event_ids_invalid");
        if (ids.Length > 0) predicates.Add(ids.Length == 1 ? $"EventID={ids[0]}" : "(" + string.Join(" or ", ids.Select(id => $"EventID={id}")) + ")");
        if (after is not null) predicates.Add($"EventRecordID > {after}");
        else if (start is not null) {
            if (!Iso8601.TryParseUtc(start, out var time)) throw new ArgumentException("start_time_utc_invalid");
            predicates.Add($"TimeCreated[@SystemTime >= '{time.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ", CultureInfo.InvariantCulture)}']");
        }
        if (through is not null && (after is not null || start is not null)) predicates.Add($"EventRecordID <= {through}");
        return predicates.Count == 0 ? "*" : "*[System[" + string.Join(" and ", predicates) + "]]";
    }

    internal static JsonObject ParseEvent(string xml, string source, string address, string channel, bool collectMessage)
    {
        if (collectMessage) throw new InvalidOperationException("message_rendering_not_supported");
        return EventXml.Parse(xml, source, address, channel);
    }

    internal static (long? Watermark, string Bound) Watermark(long? batch, long? published)
        => batch is null ? (published, "published_only") : published is null ? (batch, "batch_only")
        : batch <= published ? (batch, "batch_scoped") : (published, "published_clamped");

    internal static long? FilteredBoundary(JsonObject channel, JsonObject importStats)
    {
        var continuity = channel["continuity"] as JsonObject;
        if (channel["cursor_strategy"]?.ToString() != "record_id" || continuity?["status"]?.ToString() != "complete"
            || !True(continuity["query_exhausted"]) || continuity["selector_event_ids"] is not JsonArray { Count: > 0 }
            || !True(importStats["source_capture_continuity_persisted"])) return null;
        return Integer(channel["channel_latest_record_id_before_read"]) is > 0 and var boundary ? boundary : null;
    }

    internal static JsonObject PartialFailure(Exception? error, int written)
    {
        if (error is null) return new();
        string text = error.Message.ToLowerInvariant();
        (string Stage, string[] Markers)[] stages = [
            ("open_session", ["evtopensession", "open_remote_session", "rpc server", "logon fail"]),
            ("query", ["evtquery", "invalid query", "xpath", "malformed"]),
            ("next", ["evtnext", "no more items", "handle is invalid"]), ("render", ["evtrender", "render"]),
            ("parse", ["parse_bounded_xml", "xml", "expat", "not well-formed", "syntaxerror"]),
            ("write", ["oserror", "ioerror", "no space", "permission denied", "being used by another process"])];
        string stage = stages.FirstOrDefault(s => s.Markers.Any(text.Contains)).Stage ?? (error switch {
            UnauthorizedAccessException or IOException => "write", System.Xml.XmlException or DecoderFallbackException => "parse",
            EncoderFallbackException => "write", OutOfMemoryException => "render", _ => "unknown" });
        return new() { ["partial_kind"] = "failure", ["failure_stage"] = stage, ["partial_failure_code"] = "partial_failure_" + stage,
            ["partial_events_written"] = written, ["cursor_commit_allowed"] = false };
    }

    internal static string? BlockingFailure(IEnumerable<Exception?> errors)
    {
        var values = errors.Where(e => e is not null).Cast<Exception>().ToArray();
        string text = string.Join('\n', values.Select(e => e.Message)).ToLowerInvariant();
        string[] auth = ["windows_event_log_authentication_failed", "windows_event_log_access_denied", "ad_source_credential_mode_invalid",
            "ad_source_backend_unsupported", "ad_source_credential_profile_invalid", "ad_source_endpoint_invalid", "ad_source_credentials_unavailable"];
        var code = auth.Order(StringComparer.Ordinal).FirstOrDefault(text.Contains);
        var numbers = values.Select(e => e is System.ComponentModel.Win32Exception native ? native.NativeErrorCode & 0xffff : e.HResult & 0xffff)
            .Concat(System.Text.RegularExpressions.Regex.Matches(text, @"(?:winerror\s+|\(\s*)(\d+)(?=\b)").Select(m => int.TryParse(m.Groups[1].Value, out int n) ? n : -1)).ToHashSet();
        if (code is not null || numbers.Overlaps([1317, 1326, 1327, 1328, 1329, 1330, 1331, 1385, 1793, 1907, 1909])) return code ?? "windows_event_log_authentication_failed";
        string[] markers = ["windows_security_context_invalid", "winerror 1749", "(1749, 'evtopensession'", "(1749, \"evtopensession\"",
            "неправильный контекст безопасности", "контекст безопасности устарел", "the security context is invalid", "the security context has expired"];
        return numbers.Contains(1749) || markers.Any(text.Contains) ? "windows_security_context_invalid" : null;
    }

    internal static JsonObject Summarize(JsonArray channels)
    {
        var completed = new List<JsonObject>(); var partial = new List<JsonObject>(); var failed = new List<JsonObject>();
        bool Truncated(JsonObject row) => row["continuity"] is JsonObject c && True(c["truncated"]);
        foreach (var row in channels.OfType<JsonObject>()) {
            string? status = row["status"]?.ToString();
            bool broken = row["partial_kind"]?.ToString() == "failure" || row["cursor_commit_allowed"] is JsonValue v && v.TryGetValue<bool>(out bool allowed) && !allowed;
            if (status == "completed") { if (Truncated(row)) partial.Add(row); else completed.Add(row); }
            else if (status == "partial_timeout" && Integer(row["count"]) > 0 && !broken) partial.Add(row);
            else if (status is "failed" or "timeout" or "partial_timeout") failed.Add(row);
        }
        JsonArray Messages(IEnumerable<JsonObject> rows) => new(rows.Where(r => !string.IsNullOrEmpty(r["error"]?.ToString()))
            .Select(r => (JsonNode?)JsonValue.Create($"{r["channel"]}: {r["error"]}")).ToArray());
        var warnings = Messages(partial);
        foreach (var row in partial.Where(Truncated)) warnings.Add($"{row["channel"]}: bounded limit reached before source boundary");
        string? block = BlockingFailure(channels.OfType<JsonObject>().Select(r => r["failure_code"] ?? r["error"]).Where(n => n is not null).Select(n => new Exception(n!.ToString())));
        return new() { ["channels_total"] = channels.Count, ["channels_completed"] = completed.Count, ["channels_partial"] = partial.Count,
            ["channels_failed"] = failed.Count, ["channels_timeout"] = channels.OfType<JsonObject>().Count(r => r["status"]?.ToString() is "timeout" or "partial_timeout"),
            ["events_collected"] = completed.Concat(partial).Sum(r => Integer(r["count"]) ?? 0), ["errors"] = Messages(failed), ["warnings"] = warnings,
            ["all_failed"] = channels.Count > 0 && completed.Count + partial.Count == 0, ["partial_failed"] = completed.Count + partial.Count > 0 && failed.Count > 0,
            ["partial_warning"] = partial.Count > 0, ["terminal_block"] = block is not null, ["failure_code"] = block };
    }

    internal static bool True(JsonNode? value) => value is JsonValue v && v.TryGetValue<bool>(out bool b) && b;
    internal static long? Integer(JsonNode? value) => JsonRead.TryInteger(value, out var n) && n >= long.MinValue && n <= long.MaxValue ? (long)n : null;
}

// Acknowledges only successfully written rows. Lookahead is proof, never data;
// the caller reports why reading stopped, without introducing a runtime limit.
internal sealed class CollectorChannelCapture(string channel, long? saved, long? boundary, long? oldest,
    string? savedGeneration, string? generation, IEnumerable<int>? eventIds = null)
{
    readonly int[] selectors = (eventIds ?? []).Distinct().Order().ToArray();
    readonly (string Strategy, long? After, string? Reason) cursor = CollectorCursorContract.ResolveChannel(saved, boundary, oldest, savedGeneration, generation);
    long? maximum; int count;

    internal string XPath(string start) => CollectorCursorContract.XPath(cursor.After, start, cursor.Strategy == "record_id" ? boundary : null, selectors);

    internal void Write(string xml, string source, string address, bool collectMessage, Action<JsonObject> persist)
    {
        var row = CollectorCursorContract.ParseEvent(xml, source, address, channel, collectMessage);
        persist(row);
        var record = CollectorCursorContract.Integer(row["record_id"]);
        if (record is not null) maximum = maximum is null ? record : Math.Max(maximum.Value, record.Value);
        count++;
    }

    internal JsonObject FinishAfterStop(string? generationAfter, Func<IReadOnlyList<string>?> lookahead)
    {
        // No need to read beyond the frozen boundary. Otherwise only an
        // explicitly empty next batch proves exhaustion; null is unknown.
        bool exhausted = false;
        if (boundary is null || maximum != boundary) exhausted = lookahead() is { Count: 0 };
        return Finish(generationAfter, exhausted, stopped: true);
    }

    internal JsonObject Finish(string? generationAfter, bool exhausted, bool stopped = false, Exception? failure = null,
        bool probeFailed = false, bool postProbeFailed = false)
    {
        string status = failure is null ? "completed" : count == 0 ? "failed" : "partial_timeout";
        bool proven = exhausted || boundary is not null && maximum == boundary;
        bool stable = generation is not null && generationAfter == generation && !postProbeFailed;
        bool complete = status == "completed" && cursor.Strategy == "record_id" && saved is not null && boundary is not null
            && proven && savedGeneration is not null && generation == savedGeneration && stable && cursor.Reason is null && !probeFailed;
        var result = new JsonObject { ["channel"] = channel, ["status"] = status, ["count"] = count,
            ["error"] = failure?.Message, ["cursor_strategy"] = cursor.Strategy, ["effective_after_record_id"] = cursor.After,
            ["cursor_fallback_reason"] = cursor.Reason, ["channel_generation_identity"] = generation,
            ["channel_generation_identity_after_read"] = generationAfter, ["channel_latest_record_id_before_read"] = boundary,
            ["latest_available_record_id"] = maximum, ["batch_max_record_id"] = maximum,
            ["event_ids"] = new JsonArray(selectors.Select(n => (JsonNode?)JsonValue.Create(n)).ToArray()),
            ["continuity"] = new JsonObject { ["contract"] = "sli.source-capture-continuity.v1", ["status"] = complete ? "complete" : "not_proven",
                ["generation_stable_during_read"] = stable, ["truncated"] = stopped && !proven,
                ["query_exhausted"] = proven, ["selector_event_ids"] = new JsonArray(selectors.Select(n => (JsonNode?)JsonValue.Create(n)).ToArray()) } };
        foreach (var field in CollectorCursorContract.PartialFailure(failure, count)) result[field.Key] = field.Value?.DeepClone();
        if (CollectorCursorContract.BlockingFailure([failure]) is {} code) { result["failure_code"] = code; result["retryable"] = false; }
        return result;
    }
}
