using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;

namespace Sli.Server.Agents.Ingress;

// Source: sli_agent.snapshot_stream.validate_chunk; no persistence or receipt ownership.
public static class SnapshotChunkValidator
{
    public static void Validate(Envelope envelope, JsonObject payload, SnapshotPolicy policy, bool transportGap=false)
    {
        static ProtocolException Invalid() => new("agent_snapshot_chunk_invalid");
        try
        {
            if (!JsonRead.HasExactly(payload, "contract", "cycle_id", "family", "slot_start_utc", "chunk_index", "chunk_count", "total_objects", "total_bytes", "family_sha256", "records", "cycle_families", "domain_sid", "domain_dns", "scope")) throw Invalid();
            string Text(string name) => JsonRead.TryString(payload[name], out var value) ? value : throw Invalid();
            int Number(string name, int ceiling)
            {
                if (!JsonRead.TryInteger(payload[name], out var value) || value < 0 || value > ceiling) throw Invalid();
                return (int)value;
            }
            if (Text("contract") != envelope.ModuleId + ".chunk.v1" || policy.ModuleId != envelope.ModuleId
                || envelope.SourceInstanceId != policy.SourceId || envelope.PolicyRevision != policy.Revision
                || envelope.ModuleVersion != "1.0.0" || envelope.Channel != "snapshot" || envelope.Generation != policy.SourceId
                || !(envelope.ContinuityState == "complete" || transportGap && envelope.ContinuityState == "gap") || envelope.FilteredCount != 0 || envelope.LostCount != 0) throw Invalid();
            foreach (var key in new[] { "domain_sid", "domain_dns", "scope" })
                if (!JsonNode.DeepEquals(payload[key], policy.Config[key])) throw Invalid();
            if (!JsonNode.DeepEquals(payload["cycle_families"], policy.Config["families"])) throw Invalid();
            var after = SnapshotStream.MakeCursor(payload);
            var state = SnapshotStream.ParseCursor(after) ?? throw Invalid();
            if (envelope.CursorAfter != after) throw Invalid();
            var before = SnapshotStream.ParseCursor(envelope.CursorBefore);
            string family = Text("family");
            int index = Number("chunk_index", 2047), count = Number("chunk_count", 2048);
            if (before is null || !JsonNode.DeepEquals(before["cycle_id"], state["cycle_id"]))
            {
                if (family != policy.Families[0] || index != 0) throw Invalid();
                if (before is not null && (before["family"]!.GetValue<string>() != before["cycle_families"]!.AsArray().Last()!.GetValue<string>()
                    || before["chunk_index"]!.GetValue<int>() != before["chunk_count"]!.GetValue<int>() - 1)) throw Invalid();
            }
            else
            {
                if (!JsonNode.DeepEquals(before["cycle_families"], state["cycle_families"])) throw Invalid();
                if (before["family"]!.GetValue<string>() == family)
                {
                    if (count != before["chunk_count"]!.GetValue<int>() || index != before["chunk_index"]!.GetValue<int>() + 1) throw Invalid();
                }
                else if (before["chunk_index"]!.GetValue<int>() != before["chunk_count"]!.GetValue<int>() - 1
                    || Array.IndexOf(policy.Families, family) != Array.IndexOf(policy.Families, before["family"]!.GetValue<string>()) + 1 || index != 0) throw Invalid();
            }
            var slotText = Text("slot_start_utc");
            if (!Iso8601.TryParseUtc(slotText, out var slot) || Iso8601.Format(slot) != slotText || !Iso8601.TryParseUtc(envelope.ObservedAtUtc, out var observed) || slot > observed) throw Invalid();
            var schedule = policy.Config["schedule"]!.AsObject();
            var local = TimeZoneInfo.ConvertTime(slot, TimeZoneInfo.FindSystemTimeZoneById(schedule["timezone"]!.GetValue<string>()));
            if (local.Minute != 0 || local.Second != 0 || local.Ticks % TimeSpan.TicksPerSecond != 0 || !schedule["hours"]!.AsArray().Any(h => JsonRead.TryInteger(h, out var value) && value == local.Hour)) throw Invalid();
            int bytes = Number("total_bytes", family == "computers_v6" ? 64 * 1024 * 1024 : policy.Number("max_bytes"));
            _ = Number("total_objects", policy.Number("max_objects"));
            string hash = Text("family_sha256");
            if (hash.Length != 64 || hash.Any(c => c is not (>= '0' and <= '9' or >= 'a' and <= 'f'))) throw Invalid();
            if (count != Math.Max(1, (bytes + SnapshotStream.FragmentBytes - 1) / SnapshotStream.FragmentBytes)) throw Invalid();
            if (payload["records"] is not JsonArray records || records.Count != 1 || records[0] is not JsonObject record
                || !JsonRead.HasExactly(record, "data_b64") || !JsonRead.TryString(record["data_b64"], out var base64)) throw Invalid();
            byte[] fragment = Convert.FromBase64String(base64);
            int expected = Math.Min(SnapshotStream.FragmentBytes, bytes - index * SnapshotStream.FragmentBytes);
            if (fragment.Length != expected || Convert.ToBase64String(fragment) != base64) throw Invalid();
        }
        catch (ProtocolException error) when (error.Code == "agent_snapshot_chunk_invalid") { throw; }
        catch (Exception error) when (error is ProtocolException or AgentException or FormatException or InvalidOperationException or ArgumentException or System.Text.Json.JsonException or OverflowException or NullReferenceException or KeyNotFoundException)
        { throw Invalid(); }
    }
}
