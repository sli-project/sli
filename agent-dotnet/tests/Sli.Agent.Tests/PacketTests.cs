using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

/// <summary>The server verifies every packet with <c>sli_agent/envelope.py</c>; these tests hold the .NET packets to the same bytes.</summary>
public class PacketTests
{
    private static JsonObject Document => Vectors.Load("packets.json").AsObject();

    private static ECDsa PublicKey()
    {
        var key = ECDsa.Create();
        key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(Document["public_key_spki_b64"]!.GetValue<string>()), out _);
        return key;
    }

    public static TheoryData<string> Names()
    {
        var data = new TheoryData<string>();
        foreach (var item in Document["packets"]!.AsArray()) data.Add(item!["name"]!.GetValue<string>());
        return data;
    }

    public static TheoryData<string> InvalidNames()
    {
        var data = new TheoryData<string>();
        foreach (var item in Document["invalid"]!.AsArray()) data.Add(item!["name"]!.GetValue<string>());
        return data;
    }

    private static JsonObject Packet(string name) => Document["packets"]!.AsArray().Single(item => item!["name"]!.GetValue<string>() == name)!.AsObject();

    [Theory]
    [MemberData(nameof(Names))]
    public void VerifiesPythonSignedPackets(string name)
    {
        using var key = PublicKey();
        var item = Packet(name);
        var envelope = PacketVerifier.Verify(item["packet"], key);
        Assert.Equal(item["canonical_envelope"]!.GetValue<string>(), CanonicalJson.Serialize(envelope.ToJson()));
        Assert.Equal(item["canonical_payload"]!.GetValue<string>(), CanonicalJson.Serialize(item["packet"]!["payload"]));
        Assert.Equal(envelope.PayloadSha256, Packets.Digest(item["packet"]!["payload"]));
    }

    [Theory]
    [MemberData(nameof(Names))]
    public void BuildsTheSameEnvelopeAsPython(string name)
    {
        var item = Packet(name);
        var sample = item["sample"]!.AsObject();
        var built = new Sample(
            sample["module_id"]!.GetValue<string>(), sample["source_instance_id"]!.GetValue<string>(), sample["channel"]!.GetValue<string>(),
            sample["generation"]!.GetValue<string>(), Cursor.FromJson(sample["cursor_before"]), Cursor.FromJson(sample["cursor_after"]),
            JsonNode.Parse(sample["payload_canonical"]!.GetValue<string>())!.AsObject(), sample["module_version"]!.GetValue<string>(),
            sample["policy_revision"]!.GetValue<string>(), sample["continuity_state"]!.GetValue<string>(), sample["filtered_count"]!.GetValue<long>(),
            sample["lost_count"] is null ? null : sample["lost_count"]!.GetValue<long>());
        using var key = Helpers.NewKey();
        var packet = Packets.Make(Helpers.Signer(key), Document["agent_id"]!.GetValue<string>(), item["sequence"]!.GetValue<long>(), built,
            Iso8601.ParseUtc(item["now"]!.GetValue<string>()), () => Guid.Parse(item["packet_id"]!.GetValue<string>()));
        Assert.Equal(item["canonical_envelope"]!.GetValue<string>(), CanonicalJson.Serialize(packet.Envelope.ToJson()));
        // The signed bytes are the prefix plus that canonical envelope, and our own signature checks out against our own key.
        Assert.Equal(Packets.SignaturePrefix.Length + item["canonical_envelope"]!.GetValue<string>().Length, Packets.SignedMessage(packet.Envelope).Length);
        Assert.Equal(packet.Envelope.PacketId, PacketVerifier.Verify(packet.ToJson(), key).PacketId);
    }

    [Theory]
    [MemberData(nameof(InvalidNames))]
    public void RejectsWhatPythonRejectsWithTheSameCode(string name)
    {
        var item = Document["invalid"]!.AsArray().Single(node => node!["name"]!.GetValue<string>() == name)!.AsObject();
        using var key = PublicKey();
        var exception = Assert.Throws<ProtocolException>(() => PacketVerifier.Verify(item["packet"], key));
        Assert.Equal(item["error"]!.GetValue<string>(), exception.Code);
    }

    [Fact]
    public void ARoundTripThroughJsonTextStaysVerifiable()
    {
        using var key = Helpers.NewKey();
        var packet = Packets.Make(Helpers.Signer(key), Helpers.AgentId, 1, Helpers.Sample("", "1"), Helpers.Now);
        var parsed = JsonNode.Parse(packet.ToCanonical());
        Assert.Equal(packet.Envelope.PacketId, PacketVerifier.Verify(parsed, key).PacketId);
        Assert.Equal(packet, SignedPacket.FromJson(parsed), new PacketComparer());
    }

    [Fact]
    public void AnotherKeyCannotSign()
    {
        using var key = Helpers.NewKey();
        using var other = Helpers.NewKey();
        var packet = Packets.Make(Helpers.Signer(key), Helpers.AgentId, 1, Helpers.Sample("", "1"), Helpers.Now);
        Assert.Equal(ErrorCodes.SignatureInvalid, Assert.Throws<ProtocolException>(() => PacketVerifier.Verify(packet.ToJson(), other)).Code);
    }

    [Fact]
    public void TheSignatureIsDerEncodedLikePythonProduces()
    {
        using var key = Helpers.NewKey();
        var packet = Packets.Make(Helpers.Signer(key), Helpers.AgentId, 1, Helpers.Sample("", "1"), Helpers.Now);
        var signature = Convert.FromBase64String(packet.Signature);
        Assert.Equal(0x30, signature[0]); // ASN.1 SEQUENCE, not the fixed-width r||s form
        Assert.NotEqual(64, signature.Length);
    }

    [Fact]
    public void OnlyP256KeysSign()
    {
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        Assert.Equal(ErrorCodes.KeyUnsupported, Assert.Throws<ProtocolException>(() => new EcdsaPacketSigner(other)).Code);
    }

    [Fact]
    public void AnOversizedPacketIsNeverSigned()
    {
        using var key = Helpers.NewKey();
        var sample = Helpers.Sample("", "1") with
        {
            Payload = new JsonObject { ["contract"] = "sli.test.v1", ["records"] = new JsonArray(), ["filler"] = new string('x', Packets.MaxPacketBytes) },
        };
        Assert.Equal(ErrorCodes.PacketSizeLimit, Assert.Throws<ProtocolException>(() => Packets.Make(Helpers.Signer(key), Helpers.AgentId, 1, sample, Helpers.Now)).Code);
    }

    [Fact]
    public void AnInvalidEnvelopeIsNeverSigned()
    {
        using var key = Helpers.NewKey();
        Assert.Throws<ProtocolException>(() => Packets.Make(Helpers.Signer(key), "not-a-uuid", 1, Helpers.Sample("", "1"), Helpers.Now));
        Assert.Throws<ProtocolException>(() => Packets.Make(Helpers.Signer(key), Helpers.AgentId, 0, Helpers.Sample("", "1"), Helpers.Now));
        Assert.Throws<ProtocolException>(() => Packets.Make(Helpers.Signer(key), Helpers.AgentId, 1, Helpers.Sample("", "1", module: "Bad Module"), Helpers.Now));
    }

    private sealed class PacketComparer : IEqualityComparer<SignedPacket>
    {
        public bool Equals(SignedPacket? x, SignedPacket? y) => x?.ToCanonical() == y?.ToCanonical();

        public int GetHashCode(SignedPacket obj) => obj.ToCanonical().GetHashCode(StringComparison.Ordinal);
    }
}
