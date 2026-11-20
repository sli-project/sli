namespace Sli.Agent.Protocol;

/// <summary>A protocol violation. <see cref="Code"/> is a fixed code: it never carries input values.</summary>
public sealed class ProtocolException(string code) : Exception(code)
{
    public string Code { get; } = code;
}

/// <summary>Fixed error codes shared with the Python agent and the server.</summary>
public static class ErrorCodes
{
    public const string PacketInvalid = "agent_packet_invalid";
    public const string PacketSizeLimit = "agent_packet_size_limit";
    public const string PayloadHashMismatch = "agent_payload_hash_mismatch";
    public const string SignatureInvalid = "agent_signature_invalid";
    public const string KeyUnsupported = "agent_key_unsupported";
    public const string CollectionPacketInvalid = "collection_packet_invalid";
}
