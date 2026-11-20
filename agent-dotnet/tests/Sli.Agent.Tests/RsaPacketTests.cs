using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

public class RsaPacketTests
{
    private static JsonObject Data => Vectors.Load("rsa-packets.json").AsObject();

    private static RSA Key(JsonObject data)
    {
        var key = RSA.Create();
        key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(data["public_key_spki_b64"]!.GetValue<string>()), out _);
        return key;
    }

    [Fact]
    public void VerifiesPythonRsaPssPacket()
    {
        var data = Data;
        using var key = Key(data);
        var envelope = PacketVerifier.Verify(data["packet"], key);
        Assert.Equal(data["canonical_envelope"]!.GetValue<string>(), CanonicalJson.Serialize(envelope.ToJson()));
    }

    [Fact]
    public void RejectsPythonInvalidRsaCasesWithSameErrors()
    {
        var data = Data;
        using var key = Key(data);
        foreach (var item in data["invalid"]!.AsArray())
        {
            var error = Assert.Throws<ProtocolException>(() => PacketVerifier.Verify(item!["packet"], key));
            Assert.Equal(item!["error"]!.GetValue<string>(), error.Code);
        }
    }

    [Fact]
    public void RejectsDifferentRsaPublicKey()
    {
        var data = Data;
        using var other = RSA.Create(2048);
        Assert.Equal(ErrorCodes.SignatureInvalid, Assert.Throws<ProtocolException>(() => PacketVerifier.Verify(data["packet"], other)).Code);
    }

    [Fact]
    public void ExistingPythonEcdsaSignatureRemainsValid()
    {
        var data = Vectors.Load("packets.json");
        using var key = ECDsa.Create();
        key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(data["public_key_spki_b64"]!.GetValue<string>()), out _);
        var item = data["packets"]![0]!;
        var envelope = PacketVerifier.Verify(item["packet"], key);
        Assert.Equal(item["canonical_envelope"]!.GetValue<string>(), CanonicalJson.Serialize(envelope.ToJson()));
    }
}
