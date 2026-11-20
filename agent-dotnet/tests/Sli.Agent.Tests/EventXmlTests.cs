using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

/// <summary>The server parses every signed event again and demands an identical row: parse must agree with Python exactly.</summary>
public class EventXmlTests
{
    public static TheoryData<string> Cases()
    {
        var data = new TheoryData<string>();
        foreach (var item in Vectors.Load("event-xml.json").AsArray()) data.Add(item!["name"]!.GetValue<string>());
        return data;
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void MatchesPython(string name)
    {
        var item = Vectors.Load("event-xml.json").AsArray().Single(node => node!["name"]!.GetValue<string>() == name)!.AsObject();
        var xml = item["xml"]!.GetValue<string>();
        string Parse() => CanonicalJson.Serialize(EventXml.Parse(xml, item["source_name"]!.GetValue<string>(), item["connect_address"]!.GetValue<string>(), item["channel"]!.GetValue<string>()));
        if (item.ContainsKey("error"))
        {
            Assert.IsAssignableFrom<AgentException>(Record.Exception(Parse));
            return;
        }
        Assert.Equal(CanonicalJson.Serialize(item["row"]), Parse());
    }

    [Fact]
    public void RejectsOversizedXml() =>
        Assert.Equal("xml_size_limit_exceeded", Assert.Throws<EventXmlException>(() => EventXml.ParseBounded("<a>" + new string('x', EventXml.MaxBytes) + "</a>")).Code);

    [Fact]
    public void RejectsTooManyNodes() =>
        Assert.Equal("xml_node_limit_exceeded", Assert.Throws<EventXmlException>(() => EventXml.ParseBounded("<a>" + string.Concat(Enumerable.Repeat("<b/>", EventXml.MaxNodes)) + "</a>")).Code);

    [Fact]
    public void RejectsLoneSurrogate() => Assert.Throws<EventXmlException>(() => EventXml.ParseBounded("<a>\ud800</a>"));

    [Theory]
    [InlineData("4624", "4624")]
    [InlineData("  +4624 ", "4624")]
    [InlineData("4_624", "4624")]
    [InlineData("-0", "0")]
    [InlineData("١٢٣", "123")]
    public void PythonIntAcceptsWhatPythonAccepts(string text, string expected)
    {
        Assert.True(PythonInt.TryParse(text, out var value));
        Assert.Equal(expected, value.ToString());
    }

    [Theory]
    [InlineData("")]
    [InlineData("_1")]
    [InlineData("1_")]
    [InlineData("1__2")]
    [InlineData("0x10")]
    [InlineData("1.0")]
    [InlineData("--1")]
    public void PythonIntRejectsWhatPythonRejects(string text) => Assert.False(PythonInt.TryParse(text, out _));
}
