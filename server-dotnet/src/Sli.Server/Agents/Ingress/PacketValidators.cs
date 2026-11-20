using System.Globalization;
using System.Numerics;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Server.Agents.Ingress;

public static class HeartbeatValidator
{
    public static bool IsValid(Guid hostId, string channel, string generation, string version, string revision,
        JsonObject payload, string continuity, long filtered, long? lost) =>
        channel == "heartbeat" && generation == hostId.ToString("D") && version == "1.0.0" && revision == "1"
        && JsonNode.DeepEquals(payload, new JsonObject { ["contract"] = "sli.heartbeat.v1", ["status"] = "alive" }) && continuity == "not_proven" && filtered == 0 && lost is null;
}

public static class EventLogValidator
{
    public static JsonArray Validate(Envelope envelope, JsonObject payload, string source)
    {
        try
        {
            CollectionPacket.Validate(payload);
            var header = payload["header"]!.AsObject();
            if (header["source"]!.GetValue<string>() != source || header["channel"]!.GetValue<string>() != envelope.Channel
                || header["generation"]!.GetValue<string>() != envelope.Generation
                || envelope.CursorBefore.Strategy != "record_id" || envelope.CursorAfter.Strategy != "record_id"
                || envelope.ContinuityState is not ("not_proven" or "gap") || payload["continuity"]!["status"]!.GetValue<string>() != "not_proven"
                || envelope.FilteredCount != 0 || envelope.LostCount is not null) throw new ArgumentException();
            static BigInteger? Token(string s) => s.Length == 0 ? null : BigInteger.Parse(s, NumberStyles.Integer, CultureInfo.InvariantCulture);
            var before = Token(envelope.CursorBefore.Token); var after = Token(envelope.CursorAfter.Token);
            var cursor = header["cursor"]!.AsObject();
            if (cursor.Count != 2 || !cursor.ContainsKey("after_record_id") || !cursor.ContainsKey("last_record_id")
                || !NumberMatches(cursor["after_record_id"], before) || !NumberMatches(cursor["last_record_id"], after)) throw new ArgumentException();
            var rows = new JsonArray(); BigInteger? last = before;
            foreach (var node in payload["records"]!.AsArray())
            {
                var record = node!.AsObject();
                if (record["format"]!.GetValue<string>() != "event_xml" || record["record_id"] is null) throw new ArgumentException();
                var id = BigInteger.Parse(record["record_id"]!.ToJsonString(), CultureInfo.InvariantCulture);
                var row = record["payload"]!.AsObject();
                if (last is not null && id <= last || !JsonRead.TryInteger(row["record_id"], out var rowId) || rowId != id
                    || row["computer_name"]!.GetValue<string>() != source || row["channel"]!.GetValue<string>() != envelope.Channel)
                    throw new ArgumentException();
                rows.Add(row.DeepClone()); last = id;
            }
            if (after != last) throw new ArgumentException();
            return rows;
        }
        catch (Exception e) when (e is ArgumentException or InvalidOperationException or FormatException or OverflowException or ProtocolException or KeyNotFoundException or NullReferenceException)
        {
            throw new ProtocolException("agent_collection_packet_invalid");
        }
    }

    // Python equality treats booleans as 0/1 when comparing already validated record IDs and cursor values.
    private static bool NumberMatches(JsonNode? value, BigInteger? number)
    {
        if (number is null) return value is null;
        if (value is JsonValue scalar && scalar.TryGetValue<bool>(out bool flag)) return number == (flag ? BigInteger.One : BigInteger.Zero);
        if (JsonRead.TryInteger(value, out var integer)) return integer == number;
        if (value is not JsonValue numeric || numeric.GetValueKind() != System.Text.Json.JsonValueKind.Number) return false;
        return double.TryParse(numeric.ToJsonString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var floating)
            && double.IsFinite(floating) && Math.Truncate(floating) == floating && new BigInteger(floating) == number;
    }
}


