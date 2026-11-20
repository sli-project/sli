using System.Numerics;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Agent.Protocol;

/// <summary>The signed envelope, <c>sli.agent-envelope.v1</c> (<c>sli_agent/envelope.py: validate_envelope</c>).</summary>
public sealed partial record Envelope(
    string PacketId,
    string AgentId,
    string SourceInstanceId,
    string ModuleId,
    string ModuleVersion,
    string PolicyRevision,
    string Channel,
    string Generation,
    long Sequence,
    Cursor CursorBefore,
    Cursor CursorAfter,
    string PayloadContract,
    string PayloadSha256,
    long RecordCount,
    long PayloadBytes,
    string ObservedAtUtc,
    string ContinuityState,
    long FilteredCount,
    long? LostCount)
{
    public const string ContractId = "sli.agent-envelope.v1";

    private static readonly string[] Fields =
    [
        "contract_id", "packet_id", "agent_id", "source_instance_id", "module_id", "module_version", "policy_revision",
        "channel", "generation", "sequence", "cursor_before", "cursor_after", "payload_contract", "payload_sha256",
        "record_count", "payload_bytes", "observed_at_utc", "continuity_state", "filtered_count", "lost_count",
    ];

    private static readonly string[] ContinuityStates = ["complete", "not_proven", "gap", "filtered"];

    public JsonObject ToJson() => new()
    {
        ["contract_id"] = ContractId,
        ["packet_id"] = PacketId,
        ["agent_id"] = AgentId,
        ["source_instance_id"] = SourceInstanceId,
        ["module_id"] = ModuleId,
        ["module_version"] = ModuleVersion,
        ["policy_revision"] = PolicyRevision,
        ["channel"] = Channel,
        ["generation"] = Generation,
        ["sequence"] = Sequence,
        ["cursor_before"] = CursorBefore.ToJson(),
        ["cursor_after"] = CursorAfter.ToJson(),
        ["payload_contract"] = PayloadContract,
        ["payload_sha256"] = PayloadSha256,
        ["record_count"] = RecordCount,
        ["payload_bytes"] = PayloadBytes,
        ["observed_at_utc"] = ObservedAtUtc,
        ["continuity_state"] = ContinuityState,
        ["filtered_count"] = FilteredCount,
        ["lost_count"] = LostCount is { } lost ? JsonValue.Create(lost) : null,
    };

    /// <summary>Exactly the checks of the server and the Python agent; any failure is <c>agent_packet_invalid</c>.</summary>
    public static Envelope Parse(JsonNode? node)
    {
        static ProtocolException Invalid() => new(ErrorCodes.PacketInvalid);

        if (node is not JsonObject obj || !JsonRead.HasExactly(obj, Fields)) throw Invalid();
        if (!JsonRead.TryString(obj["contract_id"], out var contract) || contract != ContractId) throw Invalid();

        string Text(string name)
        {
            if (!JsonRead.TryString(obj[name], out var value)) throw Invalid();
            var length = JsonRead.CodePoints(value);
            if (length is < 1 or > 512) throw Invalid();
            return value;
        }

        string Uuid(string name)
        {
            var value = Text(name);
            if (!Guid.TryParseExact(value, "D", out var guid) || guid.ToString("D") != value) throw Invalid();
            return value;
        }

        long Count(string name, bool positive = false)
        {
            if (!JsonRead.TryInteger(obj[name], out var value) || value < 0 || value > long.MaxValue || positive && value == 0) throw Invalid();
            return (long)value;
        }

        var packetId = Uuid("packet_id");
        var agentId = Uuid("agent_id");
        var sourceInstance = Text("source_instance_id");
        var moduleId = Text("module_id");
        var moduleVersion = Text("module_version");
        var policyRevision = Text("policy_revision");
        var channel = Text("channel");
        var generation = Text("generation");
        var payloadContract = Text("payload_contract");
        if (!IdPattern().IsMatch(moduleId) || !IdPattern().IsMatch(payloadContract) || !VersionPattern().IsMatch(moduleVersion)) throw Invalid();
        if (!JsonRead.TryString(obj["payload_sha256"], out var sha) || !Sha256Pattern().IsMatch(sha)) throw Invalid();
        var sequence = Count("sequence", positive: true);
        var records = Count("record_count");
        var bytes = Count("payload_bytes");
        var filtered = Count("filtered_count");
        long? lost = null;
        if (!JsonRead.IsNull(obj["lost_count"]))
        {
            if (!JsonRead.TryInteger(obj["lost_count"], out var value) || value < 0 || value > long.MaxValue) throw Invalid();
            lost = (long)value;
        }
        if (!JsonRead.TryString(obj["continuity_state"], out var continuity) || !ContinuityStates.Contains(continuity)) throw Invalid();
        var before = Cursor.FromJson(obj["cursor_before"]);
        var after = Cursor.FromJson(obj["cursor_after"]);
        if (!JsonRead.TryString(obj["observed_at_utc"], out var observed) || !Iso8601.TryParseUtc(observed, out _)) throw Invalid();
        return new Envelope(packetId, agentId, sourceInstance, moduleId, moduleVersion, policyRevision, channel, generation, sequence,
            before, after, payloadContract, sha, records, bytes, observed, continuity, filtered, lost);
    }

    [GeneratedRegex(@"\A[a-z][a-z0-9_.-]{0,127}\z")]
    private static partial Regex IdPattern();

    [GeneratedRegex(@"\A\d+\.\d+\.\d+\z")]
    private static partial Regex VersionPattern();

    [GeneratedRegex(@"\A[0-9a-f]{64}\z")]
    private static partial Regex Sha256Pattern();
}
