using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Agent.Protocol;

public interface IPacketSigner
{
    /// <summary>ECDSA P-256 / SHA-256, DER-encoded: what <c>cryptography</c> produces and the server verifies.</summary>
    byte[] Sign(ReadOnlySpan<byte> message);
}

public sealed class EcdsaPacketSigner : IPacketSigner
{
    private readonly ECDsa _key;

    public EcdsaPacketSigner(ECDsa key)
    {
        var curve = key.ExportParameters(false).Curve;
        if (curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value) throw new ProtocolException(ErrorCodes.KeyUnsupported);
        _key = key;
    }

    public byte[] Sign(ReadOnlySpan<byte> message) => _key.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
}

/// <summary>A complete wire packet: <c>{"envelope", "payload", "signature"}</c>.</summary>
public sealed record SignedPacket(Envelope Envelope, JsonObject Payload, string Signature)
{
    public JsonObject ToJson() => new()
    {
        ["envelope"] = Envelope.ToJson(),
        ["payload"] = Payload.DeepClone(),
        ["signature"] = Signature,
    };

    public string ToCanonical() => CanonicalJson.Serialize(ToJson());

    public static SignedPacket FromJson(JsonNode? node)
    {
        if (node is not JsonObject obj || !JsonRead.HasExactly(obj, "envelope", "payload", "signature")
            || obj["payload"] is not JsonObject payload || !JsonRead.TryString(obj["signature"], out var signature))
        {
            throw new ProtocolException(ErrorCodes.PacketInvalid);
        }
        return new SignedPacket(Envelope.Parse(obj["envelope"]), (JsonObject)payload.DeepClone(), signature);
    }
}

public static class Packets
{
    public const int MaxPacketBytes = 60 * 1024;

    /// <summary>The signed message is this prefix (with its terminating NUL) followed by the canonical envelope.</summary>
    public static readonly byte[] SignaturePrefix = "SLI-AGENT-ENVELOPE-V1\0"u8.ToArray();

    public static string Digest(JsonNode? value) => Convert.ToHexStringLower(SHA256.HashData(CanonicalJson.ToBytes(value)));

    public static byte[] SignedMessage(Envelope envelope) => [.. SignaturePrefix, .. CanonicalJson.ToBytes(envelope.ToJson())];

    public static SignedPacket Make(IPacketSigner signer, string agentId, long sequence, Sample sample, DateTimeOffset now, Func<Guid>? packetIds = null)
    {
        var payload = sample.Payload;
        if (!JsonRead.TryString(payload["contract"], out var contract)) throw new ProtocolException(ErrorCodes.PacketInvalid);
        var records = payload["records"] switch { null => 0, JsonArray array => array.Count, _ => throw new ProtocolException(ErrorCodes.PacketInvalid) };
        var canonicalPayload = CanonicalJson.Serialize(payload);
        var envelope = new Envelope(
            (packetIds?.Invoke() ?? Guid.NewGuid()).ToString("D"), agentId, sample.SourceInstanceId, sample.ModuleId, sample.ModuleVersion,
            sample.PolicyRevision, sample.Channel, sample.Generation, sequence, sample.CursorBefore, sample.CursorAfter, contract,
            Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(canonicalPayload))), records, canonicalPayload.Length,
            Iso8601.Format(now), sample.ContinuityState, sample.FilteredCount, sample.LostCount);
        // Round trip through the validator: the agent never signs what the server would call invalid.
        envelope = Envelope.Parse(envelope.ToJson());
        var signature = Convert.ToBase64String(signer.Sign(SignedMessage(envelope)));
        var packet = new SignedPacket(envelope, payload, signature);
        if (packet.ToCanonical().Length > MaxPacketBytes) throw new ProtocolException(ErrorCodes.PacketSizeLimit);
        return packet;
    }
}

/// <summary>Checks a packet exactly as the server does (<c>sli_agent/envelope.py: verify_packet</c>).</summary>
public static partial class PacketVerifier
{
    public static Envelope Verify(JsonNode? packet, ECDsa publicKey) =>
        VerifyCore(packet, (message, signature) => publicKey.VerifyData(message, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));

    public static Envelope Verify(JsonNode? packet, RSA publicKey) =>
        VerifyCore(packet, (message, signature) => publicKey.VerifyData(message, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));

    private static Envelope VerifyCore(JsonNode? packet, Func<byte[], byte[], bool> verifySignature)
    {
        if (packet is not JsonObject obj || !JsonRead.HasExactly(obj, "envelope", "payload", "signature"))
            throw new ProtocolException(ErrorCodes.PacketInvalid);
        if (CanonicalJson.Length(packet) > Packets.MaxPacketBytes) throw new ProtocolException(ErrorCodes.PacketSizeLimit);
        var envelope = Envelope.Parse(obj["envelope"]);
        if (obj["payload"] is not JsonObject payload
            || !JsonRead.TryString(payload["contract"], out var contract) || contract != envelope.PayloadContract
            || Packets.Digest(payload) != envelope.PayloadSha256
            || CanonicalJson.Length(payload) != envelope.PayloadBytes
            || payload.ContainsKey("records") && payload["records"] is not JsonArray
            || (payload["records"] as JsonArray)?.Count is { } count && count != envelope.RecordCount
            || payload["records"] is null && envelope.RecordCount != 0)
        {
            throw new ProtocolException(ErrorCodes.PayloadHashMismatch);
        }
        if (!JsonRead.TryString(obj["signature"], out var text) || !StrictBase64().IsMatch(text) || text.Length % 4 != 0)
            throw new ProtocolException(ErrorCodes.SignatureInvalid);
        byte[] signature;
        try
        {
            signature = Convert.FromBase64String(text);
        }
        catch (FormatException)
        {
            throw new ProtocolException(ErrorCodes.SignatureInvalid);
        }
        bool valid;
        try
        {
            valid = verifySignature(Packets.SignedMessage(envelope), signature);
        }
        catch (CryptographicException)
        {
            valid = false;
        }
        if (!valid) throw new ProtocolException(ErrorCodes.SignatureInvalid);
        return envelope;
    }

    [GeneratedRegex(@"\A[A-Za-z0-9+/]*={0,2}\z")]
    private static partial Regex StrictBase64();
}
