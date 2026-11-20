using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Agent.Core;

/// <summary>Unfiltered Security reads with strict bookmark and raw XML anchor validation.</summary>
public interface INpsEventSource
{
    SourceBatch Read(JsonObject progress, int limit);
}

public sealed class NpsModule(string hostId, NpsPolicy policy, INpsEventSource source)
{
    public const string Provider = "Microsoft-Windows-Security-Auditing";
    public static JsonObject BookmarkState(Cursor cursor, string generation)
    {
        static AgentException Invalid() => new("agent_nps_cursor_invalid");
        if (cursor.Strategy != "bookmark") throw Invalid();
        if (cursor.Token.Length == 0) return new JsonObject { ["record_id"] = null, ["bookmark"] = "", ["generation"] = generation };
        var state = RadiusCursor.Token(cursor, "bookmark", "agent_nps_cursor_invalid");
        if (state.Any(p => !new[] { "record_id", "bookmark", "generation", "coverage_from_utc", "anchor_sha256" }.Contains(p.Key))
            || !state.ContainsKey("record_id") || !state.ContainsKey("bookmark") || !state.ContainsKey("generation")
            || state["record_id"] is not null && (!JsonRead.TryInteger(state["record_id"], out var id) || id <= 0 || id > long.MaxValue)
            || !JsonRead.TryString(state["bookmark"], out var bookmark) || JsonRead.CodePoints(bookmark) > 2048 || (bookmark.Length > 0) != (state["record_id"] is not null)
            || !JsonRead.TryString(state["generation"], out var gen) || gen.Length == 0 || JsonRead.CodePoints(gen) > 128
            || state.ContainsKey("anchor_sha256") && (!JsonRead.TryString(state["anchor_sha256"], out var hash) || !RadiusCursor.IsHash(hash) || state["record_id"] is null)
            || state.ContainsKey("coverage_from_utc") && (!JsonRead.TryString(state["coverage_from_utc"], out var stamp) || !Iso8601.TryParseUtc(stamp, out _) || !state.ContainsKey("anchor_sha256"))) throw Invalid();
        return state;
    }

    public Sample Collect(CapturedPosition? captured, DateTimeOffset now)
    {
        if (!policy.Active) throw new AgentException("agent_module_paused");
        if (captured is not null && captured.Generation != hostId) throw new AgentException("agent_nps_cursor_invalid");
        var before = captured?.CursorAfter ?? Cursor.Start("bookmark");
        var generation = policy.Text("event_generation");
        var progress = BookmarkState(before, generation);
        var reset = progress["generation"]!.GetValue<string>() != generation;
        if (reset) progress = BookmarkState(Cursor.Start("bookmark"), generation);
        var previous = (JsonObject)progress.DeepClone();
        var start = progress["record_id"]?.GetValue<long>();
        var batch = source.Read((JsonObject)progress.DeepClone(), policy.BatchSize);
        if (batch.BookmarkRecovered) throw new AgentException("agent_nps_read_failed");
        if (batch.Rows.Count > policy.BatchSize) throw new AgentException("agent_nps_range_invalid");
        var records = new List<PacketRecord>();
        var nodes = new JsonArray();
        long filtered = 0;
        foreach (var row in batch.Rows)
        {
            if (EventXml.NativeChannel(EventXml.ParseBounded(row.Xml)) != "Security") throw new AgentException("agent_nps_channel_invalid");
            var parsed = EventXml.Parse(NpsEventXml.Mask(row.Xml), policy.Text("source_name"), policy.Text("connect_address"), "Security");
            if (!JsonRead.TryInteger(parsed["record_id"], out var id) || id <= 0 || id > long.MaxValue || progress["record_id"] is not null && id <= progress["record_id"]!.GetValue<long>()
                || row.Bookmark.Length == 0 || JsonRead.CodePoints(row.Bookmark) > 2048) throw new AgentException("agent_nps_range_invalid");
            if (parsed["provider_name"]?.ToString() == Provider && JsonRead.TryInteger(parsed["event_id"], out var eventId) && (eventId == 6272 || eventId == 6273))
            {
                var node = new JsonObject { ["format"] = "event_xml", ["record_id"] = JsonRead.Integer(id), ["payload"] = parsed.DeepClone() };
                nodes.Add(node);
                if (CanonicalJson.Length(nodes) > NpsPolicy.MaxPayloadBytes - 4096)
                {
                    nodes.RemoveAt(nodes.Count - 1);
                    if (records.Count == 0) throw new AgentException("agent_nps_size_limit");
                    break;
                }
                records.Add(new("event_xml", id, parsed));
            }
            else filtered++;
            progress = new JsonObject { ["record_id"] = (long)id, ["bookmark"] = row.Bookmark, ["generation"] = generation, ["anchor_sha256"] = Hash(row.Xml) };
        }
        var drained = false;
        if (progress["record_id"] is not null)
        {
            var probe = source.Read((JsonObject)progress.DeepClone(), 1);
            if (probe.BookmarkRecovered) throw new AgentException("agent_nps_read_failed");
            drained = probe.Rows.Count == 0;
        }
        var contiguous = start is not null && progress["record_id"]!.GetValue<long>() - start == records.Count + filtered;
        progress.Remove("coverage_from_utc");
        var origin = contiguous && !reset ? previous["coverage_from_utc"]?.GetValue<string>() : null;
        if (origin is not null && Iso8601.ParseUtc(origin) > now) origin = null;
        var continuity = new JsonObject { ["status"] = "not_proven" };
        if (drained && progress["anchor_sha256"] is not null)
        {
            if (origin is not null && Iso8601.ParseUtc(origin) < now)
                continuity = new JsonObject { ["status"] = "complete", ["from_utc"] = origin, ["to_utc"] = Iso8601.Format(now) };
            progress["coverage_from_utc"] = origin ?? Iso8601.Format(now);
        }
        else if (origin is not null) progress["coverage_from_utc"] = origin;
        var payload = CollectionPacket.Make(policy.Text("source_name"), "Security", generation,
            new JsonObject { ["after_record_id"] = start, ["last_record_id"] = progress["record_id"]?.DeepClone() }, records, "not_proven",
            new JsonObject { ["normalizer"] = "windows-nps-radius-v1", ["filtered_count"] = filtered, ["channel_reset"] = reset, ["tail_drained"] = drained }, now);
        payload["continuity"] = continuity;
        return new(NpsPolicy.Nps, policy.SourceId, "Security", hostId, before, new("bookmark", CanonicalJson.Serialize(progress)), payload,
            PolicyRevision: policy.Revision, FilteredCount: filtered, ContinuityState: reset ? "gap" : filtered > 0 ? "filtered" : "not_proven", LostCount: reset ? null : 0);
    }
    internal static string Hash(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
}
