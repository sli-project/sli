using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Server.Storage.Direct;
using Xunit;

namespace Sli.Server.Tests.Storage;

// Parity with tests/storage/test_xml_safety.py and its importer consumer.
public sealed class XmlSafetyTests
{
    [Fact]
    public void Normal_event_document_is_accepted()
    {
        var root = EventXml.ParseBounded("<Event><EventData><Data Name='User'>alice</Data></EventData></Event>");
        Assert.Equal("Event", root.Name.LocalName);
        Assert.Equal("alice", root.Element("EventData")!.Element("Data")!.Value);
    }

    [Theory]
    [InlineData("<!DOCTYPE Event [<!ENTITY x 'secret'>]><Event>&x;</Event>")]
    [InlineData("<!DOCTYPE Event><Event />")]
    [InlineData("<!ENTITY x 'secret'><Event />")]
    [InlineData("<!-- <!doctype Event> --><Event />")]
    public void Dtd_and_entities_are_rejected_even_after_long_prefix(string xml)
    {
        Assert.Equal("xml_dtd_or_entity_forbidden",
            Assert.Throws<EventXmlException>(() => EventXml.ParseBounded(new string(' ', 5000) + xml)).Code);
    }

    [Fact]
    public void Size_boundary_counts_utf8_bytes()
    {
        // <E></E> is seven bytes; each non-ASCII payload character is two.
        string xml = "<E>" + new string('\u00e9', (EventXml.MaxBytes - 8) / 2) + "x</E>";
        Assert.Equal("E", EventXml.ParseBounded(xml).Name.LocalName);
        Assert.Equal("xml_size_limit_exceeded",
            Assert.Throws<EventXmlException>(() => EventXml.ParseBounded(xml + " ")).Code);
    }

    [Fact]
    public void Depth_boundary_counts_root_as_one()
    {
        string xml = string.Concat(Enumerable.Repeat("<a>", EventXml.MaxDepth - 1)) + "<c />"
            + string.Concat(Enumerable.Repeat("</a>", EventXml.MaxDepth - 1));
        Assert.Equal("a", EventXml.ParseBounded(xml).Name.LocalName);
        Assert.Equal("xml_depth_limit_exceeded",
            Assert.Throws<EventXmlException>(() => EventXml.ParseBounded("<a>" + xml + "</a>")).Code);
    }

    [Fact]
    public void Node_boundary_counts_elements_including_root()
    {
        string xml = "<a>" + string.Concat(Enumerable.Repeat("<b />", EventXml.MaxNodes - 1)) + "</a>";
        Assert.Equal(EventXml.MaxNodes - 1, EventXml.ParseBounded(xml).Elements().Count());
        Assert.Equal("xml_node_limit_exceeded",
            Assert.Throws<EventXmlException>(() => EventXml.ParseBounded(xml.Replace("</a>", "<c /></a>"))).Code);
    }

    // Construct invalid UTF-16 at runtime: attribute metadata cannot preserve a lone surrogate.
    public static TheoryData<string, string> ParseFailures => new()
    {
        { "<Event><broken></Event>", "ParseError" },
        { "<!DOCTYPE Event [<!ENTITY x 'secret'>]><Event>&x;</Event>", "UnsafeXmlError" },
        { "<Event>\ud800</Event>", "UnicodeEncodeError" },
    };

    [Theory]
    [MemberData(nameof(ParseFailures))]
    public void Importer_preserves_parse_failure_as_data_quality(string xml, string errorType)
    {
        var expected = new JsonObject
        {
            ["_sli_data_quality"] = new JsonObject
            {
                ["event_data_parse_status"] = "failed",
                ["error_type"] = errorType,
            },
        };
        Assert.True(JsonNode.DeepEquals(expected, DirectNativeEvent.Data(new JsonObject { ["xml"] = xml })));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Missing_xml_is_empty_event_data(string? xml) =>
        Assert.Empty(DirectNativeEvent.Data(new JsonObject { ["xml"] = xml }));
}
