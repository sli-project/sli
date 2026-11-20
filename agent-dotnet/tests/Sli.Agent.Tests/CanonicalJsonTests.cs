using System.Text.Json.Nodes;
using System.Security.Cryptography;
using Sli.Agent.Protocol;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

public class CanonicalJsonTests
{
    public static TheoryData<string> Cases()
    {
        var data = new TheoryData<string>();
        foreach (var item in Vectors.Load("canonical.json").AsArray()) data.Add(item!["name"]!.GetValue<string>());
        return data;
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void MatchesPythonByteForByte(string name)
    {
        var item = Vectors.Load("canonical.json").AsArray().Single(node => node!["name"]!.GetValue<string>() == name)!;
        Assert.Equal(item["canonical"]!.GetValue<string>(), CanonicalJson.Serialize(item["value"]));
    }

    [Fact]
    public void OrdersKeysByCodePointNotUtf16()
    {
        var node = new JsonObject { ["\U00010000"] = 1, ["\uffff"] = 2 };
        Assert.Equal("{\"\\uffff\":2,\"\\ud800\\udc00\":1}", CanonicalJson.Serialize(node));
    }

    [Fact]
    public void FiniteNumbersMatchPythonSourceBytesIncludingNegativeZeroAndBigIntegers()
    {
        foreach (var item in Vectors.Load("canonical-floats.json")["cases"]!.AsArray())
            Assert.Equal(item!["expected"]!.GetValue<string>(), CanonicalJson.Serialize(JsonNode.Parse(item["raw"]!.GetValue<string>())));
        Assert.Equal("1.5", CanonicalJson.Serialize(JsonValue.Create(1.5)));
        Assert.Equal("-0.0", CanonicalJson.Serialize(JsonValue.Create(-0.0)));
    }

    [Fact]
    public void NonfiniteNumbersAreRejected()
    {
        Assert.Throws<ProtocolException>(() => CanonicalJson.Serialize(JsonNode.Parse("1e400")));
        Assert.Throws<ProtocolException>(() => CanonicalJson.Serialize(JsonValue.Create(double.NaN)));
        Assert.Throws<ProtocolException>(() => CanonicalJson.Serialize(JsonValue.Create(double.PositiveInfinity)));
        Assert.Throws<ProtocolException>(() => CanonicalJson.Serialize(JsonValue.Create(double.NegativeInfinity)));
    }

    [Fact]
    public void VerifiesPythonSignedEventPacketWithFiniteFloat()
    {
        var data=Vectors.Load("canonical-floats.json");
        using var key=ECDsa.Create();
        key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(data["public_spki"]!.GetValue<string>()),out _);
        var packet=data["packet"]!;
        var envelope=PacketVerifier.Verify(packet,key);
        Assert.Equal(data["payload_canonical"]!.GetValue<string>(),CanonicalJson.Serialize(packet["payload"]));
        Assert.Equal(data["envelope_canonical"]!.GetValue<string>(),CanonicalJson.Serialize(envelope.ToJson()));
    }

    [Fact]
    public void NegativeZeroIsZero() => Assert.Equal("0", CanonicalJson.Serialize(JsonNode.Parse("-0")));

    [Fact]
    public void IsAsciiOnly() => Assert.All(CanonicalJson.ToBytes(JsonValue.Create("日本語 \U0001F600")), b => Assert.True(b < 0x80));
}
