using System.Text.Json.Nodes;

namespace Sli.Agent.Protocol;

/// <summary>
/// The server's answer to a packet (<c>sli.agent-receipt.v1</c>). Only an exact, matching
/// <c>committed</c>/<c>duplicate</c> receipt proves delivery. An exact expiration or module-disable refusal
/// permits deletion only with a durable gap checkpoint.
/// </summary>
public static class Receipt
{
    public const string ContractId = "sli.agent-receipt.v1";

    /// <summary>An exact permanent refusal permits discarding this packet, never claiming delivery.</summary>
    public static bool IsExpired(Envelope envelope, JsonNode? node) => IsRefusal(envelope,node,"agent_packet_expired");

    public static bool IsModuleDisabled(Envelope envelope, JsonNode? node) => IsRefusal(envelope,node,"module_disabled");

    private static bool IsRefusal(Envelope envelope, JsonNode? node,string code) =>
        node is JsonObject receipt
        && JsonRead.TryString(receipt["contract_id"], out var contract) && contract == ContractId
        && Status(receipt) == "rejected" && ErrorCode(receipt) == code
        && JsonRead.TryString(receipt["packet_id"], out var id) && id == envelope.PacketId
        && JsonRead.TryString(receipt["payload_sha256"], out var sha) && sha == envelope.PayloadSha256
        && receipt.ContainsKey("committed_cursor") && JsonRead.IsNull(receipt["committed_cursor"])
        && receipt.ContainsKey("evidence_ref") && JsonRead.IsNull(receipt["evidence_ref"])
        && receipt.ContainsKey("committed_at_utc") && JsonRead.IsNull(receipt["committed_at_utc"]);

    public static bool IsDeliveryProof(Envelope envelope, JsonNode? node)
    {
        if (node is not JsonObject receipt) return false;
        if (!JsonRead.TryString(receipt["contract_id"], out var contract) || contract != ContractId) return false;
        if (!JsonRead.TryString(receipt["status"], out var status) || status is not ("committed" or "duplicate")) return false;
        if (!JsonRead.TryString(receipt["packet_id"], out var packetId) || packetId != envelope.PacketId) return false;
        if (!JsonRead.TryString(receipt["payload_sha256"], out var sha) || sha != envelope.PayloadSha256) return false;
        if (!SameCursor(receipt["committed_cursor"], envelope.CursorAfter)) return false;
        if (!JsonRead.TryString(receipt["evidence_ref"], out var evidence) || evidence.Length == 0) return false;
        if (!JsonRead.TryString(receipt["committed_at_utc"], out var committed) || !Iso8601.TryParseUtc(committed, out _)) return false;
        return JsonRead.IsNull(receipt["error_code"]);
    }

    private static bool SameCursor(JsonNode? node, Cursor expected) =>
        node is JsonObject obj && JsonRead.HasExactly(obj, "strategy", "token")
        && JsonRead.TryString(obj["strategy"], out var strategy) && strategy == expected.Strategy
        && JsonRead.TryString(obj["token"], out var token) && token == expected.Token;

    /// <summary>The server's refusal reason, if any, for logs and the local status file. Never a data value.</summary>
    public static string? ErrorCode(JsonNode? node) =>
        node is JsonObject receipt && JsonRead.TryString(receipt["error_code"], out var code) ? code : null;

    public static string? Status(JsonNode? node) =>
        node is JsonObject receipt && JsonRead.TryString(receipt["status"], out var status) ? status : null;
}
