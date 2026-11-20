using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Ingress;

namespace Sli.Server.Agents.SnapshotPublication;

public sealed record SnapshotCycleRow(JsonObject Envelope, JsonObject Payload, string EnvelopeSha256);

// Frozen transport attestation; no database updates or publication decisions.
public static class SnapshotCycleAssembly
{
    public static IReadOnlyDictionary<string, byte[]>? ValidateAndAssemble(string cycleId, string agentId, string slot,
        SnapshotPolicy policy, IReadOnlyList<SnapshotCycleRow> rows)
    {
        try
        {
            var families = policy.Families.ToDictionary(x => x, _ => new List<(JsonObject Payload, byte[] Fragment)>(), StringComparer.Ordinal);
            Envelope? previous = null;
            foreach (var row in rows)
            {
                var e = Envelope.Parse(row.Envelope);
                var p = row.Payload;
                if (e.AgentId != agentId || e.ModuleId != policy.ModuleId || p["cycle_id"]!.GetValue<string>() != cycleId
                    || p["slot_start_utc"]!.GetValue<string>() != slot || Packets.Digest(row.Envelope) != row.EnvelopeSha256
                    || Packets.Digest(p) != e.PayloadSha256 || CanonicalJson.Length(p) != e.PayloadBytes || e.RecordCount != 1)
                    throw Invalid();
                SnapshotChunkValidator.Validate(e, p, policy);
                if (previous is not null && (previous.Sequence == long.MaxValue || e.Sequence != previous.Sequence + 1 || e.CursorBefore != previous.CursorAfter)) throw Invalid();
                previous = e;
                string family = p["family"]!.GetValue<string>();
                families[family].Add((p, Convert.FromBase64String(p["records"]![0]!["data_b64"]!.GetValue<string>())));
            }
            long objects = 0, bytes = 0;
            var output = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            foreach (var (family, chunks) in families)
            {
                if (chunks.Count == 0) return null;
                var head = chunks[0].Payload;
                if (chunks.Count != head["chunk_count"]!.GetValue<int>()) return null;
                using var data = new MemoryStream();
                for (int i=0; i<chunks.Count; i++)
                {
                    var (p, fragment) = chunks[i];
                    if (p["chunk_index"]!.GetValue<int>() != i) throw Invalid();
                    foreach (var name in new[] { "chunk_count", "total_objects", "total_bytes", "family_sha256" })
                        if (!JsonNode.DeepEquals(p[name], head[name])) throw Invalid();
                    data.Write(fragment);
                }
                var raw = data.ToArray();
                if (raw.Length != head["total_bytes"]!.GetValue<int>() || Convert.ToHexStringLower(SHA256.HashData(raw)) != head["family_sha256"]!.GetValue<string>()) throw Invalid();
                long count = head["total_objects"]!.GetValue<int>();
                objects = policy.ModuleId == SnapshotPolicy.Gpo ? Math.Max(objects, count) : checked(objects + count);
                if (family != "computers_v6") bytes = checked(bytes + raw.Length);
                if (objects > policy.Number("max_objects") || bytes > policy.Number("max_bytes")) throw Invalid();
                output.Add(family, raw);
            }
            return output;
        }
        catch (Exception e) when (e is ProtocolException or AgentException or FormatException or InvalidOperationException or ArgumentException or System.Text.Json.JsonException or OverflowException or NullReferenceException or KeyNotFoundException)
        { throw Invalid(); }
    }
    private static ProtocolException Invalid() => new("agent_snapshot_cycle_invalid");
}
