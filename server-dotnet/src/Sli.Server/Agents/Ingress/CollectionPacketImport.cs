using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Protocol;

namespace Sli.Server.Agents.Ingress;

// Local acquisition adapters: sli_collect.snapshots and collection_packet_import.py.
// These are import inputs, not an agent authorization boundary. Caller owns the worker session and transaction.
public static class CollectionPacketImport
{
    public static IEnumerable<JsonObject> ReadEventJsonl(string path)
    {
        if (!File.Exists(path)) yield break;
        using var reader = new StreamReader(path, new UTF8Encoding(false, true), detectEncodingFromByteOrderMarks: true);
        while (reader.ReadLine() is { } line)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            if (JsonNode.Parse(line) is not JsonObject value) throw new ProtocolException("jsonl_row_must_be_object");
            if (value.ContainsKey("contract"))
                foreach (var row in AgentCollectionRows.ExtractEvents(value)) yield return row!.AsObject();
            else yield return value;
        }
    }

    public static JsonObject ReadSnapshotPacket(string path, string channel, DateTimeOffset observedAt, string? source = null)
    {
        // Existing snapshot wire bound, including a second check if the file grows during the read.
        const int maximum = 25 * 1024 * 1024;
        using var stream = File.OpenRead(path);
        if (stream.Length > maximum) throw new ProtocolException("snapshot_packet_size_limit");
        using var bytes = new MemoryStream();
        var buffer = new byte[8192];
        int count;
        while ((count = stream.Read(buffer, 0, Math.Min(buffer.Length, maximum + 1 - (int)bytes.Length))) > 0)
        {
            bytes.Write(buffer, 0, count);
            if (bytes.Length > maximum) throw new ProtocolException("snapshot_packet_size_limit");
        }
        byte[] raw = bytes.ToArray();
        string? digest = File.ReadAllText(path + ".sha256", Encoding.ASCII).Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        if (!string.Equals(digest, Convert.ToHexStringLower(SHA256.HashData(raw)), StringComparison.OrdinalIgnoreCase))
            throw new ProtocolException("snapshot_packet_digest_mismatch");
        string json = new UTF8Encoding(false, true).GetString(raw);
        if (json.StartsWith('\uFEFF')) json = json[1..];
        var bundle = JsonNode.Parse(json)!.AsObject();
        return SnapshotPacket(bundle, source ?? bundle["domain"]!["sid"]!.GetValue<string>(), channel, observedAt);
    }

    public static JsonObject SnapshotPacket(JsonObject bundle, string source, string channel, DateTimeOffset observedAt)
    {
        string run = bundle["run_id"]!.GetValue<string>();
        var sections = bundle["sections"] as JsonArray;
        bool complete = sections is { Count: > 0 } && sections.All(s => s?["status"]?.ToString() == "complete");
        return CollectionPacket.Make(source, channel, run, new JsonObject { ["run_id"] = run },
            [new("snapshot_json", null, bundle)], complete ? "complete" : "not_proven", null, observedAt);
    }

    public static JsonObject SnapshotBundle(JsonObject packet)
    {
        CollectionPacket.Validate(packet);
        var records = packet["records"]!.AsArray();
        if (records.Count != 1 || records[0]!["format"]!.GetValue<string>() != "snapshot_json")
            throw new ProtocolException("collection_packet_snapshot_invalid");
        var bundle = records[0]!["payload"]!.AsObject();
        var header = packet["header"]!.AsObject();
        if (!JsonNode.DeepEquals(bundle["run_id"], header["generation"])
            || !JsonNode.DeepEquals(header["cursor"], new JsonObject { ["run_id"] = bundle["run_id"]?.DeepClone() })
            || !JsonNode.DeepEquals(bundle["domain"]?["sid"], header["source"]))
            throw new ProtocolException("collection_packet_snapshot_mismatch");
        return Sli.Server.Ad.AdContextBundle.Normalize(bundle);
    }

    public static Task<Dictionary<string, long>> ImportSnapshotAsync(NpgsqlConnection db, NpgsqlTransaction tx, long domain,
        JsonObject packet, CancellationToken ct) => Sli.Server.Ad.AdContextStore.ImportAsync(db, tx, domain, SnapshotBundle(packet), ct);
}
