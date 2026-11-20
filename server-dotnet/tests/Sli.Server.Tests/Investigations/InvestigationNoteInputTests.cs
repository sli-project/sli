using System.Text.Json;
using Sli.Server.Auth;
using Sli.Server.Investigations;
using Xunit;
namespace Sli.Server.Tests.Investigations;
public sealed class InvestigationNoteInputTests
{
    static JsonElement J(string s)=>JsonDocument.Parse(s).RootElement.Clone();
    [Theory]
    [InlineData("true","True")]
    [InlineData("42","42")]
    [InlineData("1e0","1.0")]
    [InlineData("1.0","1.0")]
    [InlineData("1e16","1e+16")]
    [InlineData("1e-5","1e-05")]
    [InlineData("1e15","1000000000000000.0")]
    [InlineData("[null, true, 1e0]","[None, True, 1.0]")]
    [InlineData("{\"a\":\"x\"}","{'a': 'x'}")]
    [InlineData("[\"a'b\"]","[\"a'b\"]")]
    [InlineData("[\"\\u0001\\u00a0\"]","['\\x01\\xa0']")]
    public void BodyCoercionMatchesPython(string value,string expected)=>Assert.Equal(expected,InvestigationAccess.CleanBody(J("{\"body\":"+value+"}")));
    [Theory]
    [InlineData("[\"\\ud800\"]", "['\\ud800']")]
    [InlineData("[\"\\udfff\"]", "['\\udfff']")]
    [InlineData("{\"\\ud800\":\"\\udfff\"}", "{'\\ud800': '\\udfff'}")]
    [InlineData("[{\"nested\":[\"x\\ud800y\",\"\\ud83d\\ude00\"]}]", "[{'nested': ['x\\ud800y', '😀']}]")]
    [InlineData("{\"a\":1,\"a\":2}", "{'a': 2}")]
    [InlineData("{\"a\":1,\"b\":2,\"a\":3}", "{'a': 3, 'b': 2}")]
    [InlineData("[{\"a\":1,\"b\":{\"x\":0,\"y\":1,\"x\":2},\"a\":3}]", "[{'a': 3, 'b': {'x': 2, 'y': 1}}]")]
    [InlineData("{\"a\":1,\"b\":2,\"\\u0061\":3}", "{'a': 3, 'b': 2}")]
    [InlineData("{\"\\ud800\":1,\"b\":2,\"\\ud800\":3}", "{'\\ud800': 3, 'b': 2}")]
    [InlineData("[\"\\\\ud800\",\"\\b\\f\\n\\r\\t\\/\\\\\\\"\"]", "['\\\\ud800', '\\x08\\x0c\\n\\r\\t/\\\\\"']")]
    public void ReviewedNestedJsonCoercionMatchesPython(string value,string expected)=>Assert.Equal(expected,InvestigationAccess.CleanBody(J("{\"body\":"+value+"}")));
    [Theory]
    [InlineData("null")][InlineData("false")][InlineData("0")][InlineData("0.0")][InlineData("[]")][InlineData("{}")][InlineData("\" \\u001c \"")]
    public void FalseyAndPythonWhitespaceBodiesFail(string value)=>Assert.Equal("invalid_note",Assert.Throws<InvestigationException>(()=>InvestigationAccess.CleanBody(J("{\"body\":"+value+"}"))).Code);
    [Fact]
    public void TruncationCountsUnicodeCodePointsAfterStrip()
    {
        string value="\u001c "+string.Concat(Enumerable.Repeat("😀",4001))+" \u001f";
        string clean=InvestigationAccess.CleanBody(JsonSerializer.SerializeToElement(new{body=value}));
        Assert.Equal(4000,clean.EnumerateRunes().Count()); Assert.Equal(8000,clean.Length);
    }
    [Theory]
    [InlineData("00012","12")][InlineData("١٢","12")]
    [InlineData("{12345678-1234-1234-1234-123456789abc}","12345678-1234-1234-1234-123456789abc")]
    [InlineData("urn:uuid:12345678123412341234123456789abc","12345678-1234-1234-1234-123456789abc")]
    public void IdentityMatchesPython(string raw,string expected)=>Assert.Equal(expected,InvestigationIdentity.Parse(raw).Display);
    [Theory]
    [InlineData("0","Investigation ID must be positive")][InlineData("-1","Investigation ID is invalid")][InlineData("nope","Investigation ID is invalid")]
    public void IdentityErrors(string raw,string message)=>Assert.Equal(message,Assert.Throws<InvestigationException>(()=>InvestigationIdentity.Parse(raw)).Message);
    [Fact]
    public void ActorUsesUsernameLabelTypeThenOperator()
    {
        Assert.Equal("user",InvestigationAccess.Actor(new("session",1,"viewer",Username:"user",Label:"key")));
        Assert.Equal("key",InvestigationAccess.Actor(new("api_key",1,"viewer",Label:"key")));
        Assert.Equal("session",InvestigationAccess.Actor(new("session",1,"viewer")));
        Assert.Equal("operator",InvestigationAccess.Actor(new("",0,"operator")));
    }
}
