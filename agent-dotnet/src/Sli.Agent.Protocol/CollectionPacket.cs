using System.Numerics;
using System.Text.Json.Nodes;

namespace Sli.Agent.Protocol;

public sealed record PacketRecord(string Format, BigInteger? RecordId, JsonNode Payload);

/// <summary>The acquisition payload <c>sli.collection-packet.v1</c> (<c>sli_collect/packets.py</c>).</summary>
public static class CollectionPacket
{
    public const string Contract = "sli.collection-packet.v1";
    public static readonly IReadOnlySet<string> Formats = new HashSet<string> { "event_xml", "file_action", "accounting_line", "snapshot_json" };
    private static readonly string[] Continuity = ["complete", "not_proven"];

    public static JsonObject Make(string source, string channel, string? generation, JsonObject cursor, IReadOnlyList<PacketRecord> records,
        string continuityStatus, JsonObject? context, DateTimeOffset observedAt)
    {
        var ids = records.Where(record => record.RecordId is not null).Select(record => record.RecordId!.Value).ToList();
        var packet = new JsonObject
        {
            ["contract"] = Contract,
            ["header"] = new JsonObject
            {
                ["source"] = source,
                ["channel"] = channel,
                ["generation"] = generation,
                ["record_id_range"] = new JsonObject
                {
                    ["first"] = ids.Count > 0 ? JsonRead.Integer(ids.Min()) : null,
                    ["last"] = ids.Count > 0 ? JsonRead.Integer(ids.Max()) : null,
                },
                ["cursor"] = cursor.DeepClone(),
                ["observed_at_utc"] = Iso8601.Format(observedAt),
            },
            ["records"] = new JsonArray(records.Select(record => (JsonNode?)new JsonObject
            {
                ["format"] = record.Format,
                ["record_id"] = record.RecordId is { } id ? JsonRead.Integer(id) : null,
                ["payload"] = record.Payload.DeepClone(),
            }).ToArray()),
            ["continuity"] = new JsonObject { ["status"] = continuityStatus },
            ["context"] = context?.DeepClone() ?? new JsonObject(),
        };
        Validate(packet);
        return (JsonObject)packet.DeepClone();
    }

    /// <summary>The envelope-level check only; source-specific rules stay with the server importer.</summary>
    public static void Validate(JsonNode? node)
    {
        static ProtocolException Invalid() => new(ErrorCodes.CollectionPacketInvalid);

        if (node is not JsonObject packet || !JsonRead.HasExactly(packet, "contract", "header", "records", "continuity", "context")
            || !JsonRead.TryString(packet["contract"], out var contract) || contract != Contract
            || packet["header"] is not JsonObject header
            || !JsonRead.HasExactly(header, "source", "channel", "generation", "record_id_range", "cursor", "observed_at_utc"))
        {
            throw Invalid();
        }
        foreach (var name in new[] { "source", "channel", "observed_at_utc" })
        {
            if (!JsonRead.TryString(header[name], out var text) || string.IsNullOrWhiteSpace(text)) throw Invalid();
        }
        if (!JsonRead.IsNull(header["generation"]) && (!JsonRead.TryString(header["generation"], out var generation) || string.IsNullOrWhiteSpace(generation)))
            throw Invalid();
        JsonRead.TryString(header["observed_at_utc"], out var observed);
        if (!Iso8601.TryParseUtc(observed, out _) || header["cursor"] is not JsonObject || packet["context"] is not JsonObject) throw Invalid();
        if (packet["continuity"] is not JsonObject continuity || !JsonRead.TryString(continuity["status"], out var status) || !Continuity.Contains(status)) throw Invalid();
        if (packet["records"] is not JsonArray records) throw Invalid();

        var ids = new List<BigInteger>();
        foreach (var item in records)
        {
            if (item is not JsonObject record || !JsonRead.HasExactly(record, "format", "record_id", "payload")
                || !JsonRead.TryString(record["format"], out var format) || !Formats.Contains(format))
            {
                throw Invalid();
            }
            BigInteger? recordId = null;
            if (!JsonRead.IsNull(record["record_id"]))
            {
                if (!JsonRead.TryInteger(record["record_id"], out var id) || id < 0) throw Invalid();
                recordId = id;
            }
            var payload = record["payload"];
            if (format == "accounting_line" ? !JsonRead.TryString(payload, out _) : payload is not JsonObject) throw Invalid();
            if (format is not ("event_xml" or "file_action"))
            {
                if (recordId is not null) throw Invalid();
            }
            else if (format == "event_xml")
            {
                var row = (JsonObject)payload!;
                if (!JsonRead.TryString(row["xml"], out _) || !row.ContainsKey("computer_name") || !row.ContainsKey("channel")) throw Invalid();
            }
            else if (recordId is null || recordId<=0) throw Invalid();
            if (recordId is { } value) ids.Add(value);
        }
        if (header["record_id_range"] is not JsonObject range || !JsonRead.HasExactly(range, "first", "last")) throw Invalid();
        foreach (var name in new[] { "first", "last" })
        {
            if (!JsonRead.IsNull(range[name]) && (!JsonRead.TryInteger(range[name], out var bound) || bound < 0)) throw Invalid();
        }
        BigInteger? first = JsonRead.TryInteger(range["first"], out var f) ? f : null;
        BigInteger? last = JsonRead.TryInteger(range["last"], out var l) ? l : null;
        if (ids.Count == 0 ? first is not null || last is not null : first != ids.Min() || last != ids.Max()) throw Invalid();
    }
}
