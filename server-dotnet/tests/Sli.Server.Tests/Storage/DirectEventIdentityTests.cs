using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Server.Agents.Consumer;
using Sli.Server.Storage.Direct;
using Xunit;

namespace Sli.Server.Tests.Storage;

public class DirectEventIdentityTests
{
    private static JsonObject Row(string metadata) => EventXml.Parse(
        $"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><EventRecordID>5</EventRecordID><TimeCreated SystemTime='2026-10-07T00:00:00Z'/><Channel>Security</Channel><Computer>dc.example.test</Computer>{metadata}</System><EventData><Data Name='LogonType'>3</Data></EventData></Event>",
        "dc.example.test", "192.0.2.1", "Security");

    public static TheoryData<string, string> InvalidIntegers()
    {
        var data = new TheoryData<string, string>();
        foreach (string tag in new[] { "Version", "Level", "Task", "Opcode" })
            foreach (string value in new[] { "not-an-integer", " ", "1.5", "0x10", "1__0", "+" })
                data.Add(tag, value);
        return data;
    }

    [Theory]
    [MemberData(nameof(InvalidIntegers))]
    public void Invalid_optional_xml_integer_blocks_complete_batch_before_reservations(string tag, string value)
    {
        var row = Row($"<{tag}>{value}</{tag}>");
        Assert.Null(row[tag.ToLowerInvariant()]); // Intake attestation alone cannot detect this source rejection.
        Assert.Throws<InvalidDataException>(() => DirectEventIdentity.Hash(row));
        var rows = new JsonArray(Row(""), row, Row(""));
        var error = Assert.Throws<InvalidDataException>(() => DirectAdDcPacket.PrepareBatch(rows));
        Assert.Equal("storage_v2_event_profile_pending", error.Message);
        var diagnostic = JsonNode.Parse(AdDcProjectionFailure.Describe(error, AdDcProjectionStep.PrepareBatch))!;
        Assert.Equal("storage_v2_event_profile_pending", (string?)diagnostic["reason"]);
        Assert.Equal("prepare_batch", (string?)diagnostic["step"]);
    }

    // Exact digests from frozen Python parse_event_xml -> event_identity_hash.
    [Theory]
    [InlineData("", "6c0758eb7786c1c7bfefbae54e6ad31709d436236b5988b86d506a67c70babaf")]
    [InlineData("<Version/><Level/><Task/><Opcode/>", "6c0758eb7786c1c7bfefbae54e6ad31709d436236b5988b86d506a67c70babaf")]
    [InlineData("<Version> +1_0 </Version><Level>٢</Level><Task>2147483648</Task><Opcode>-1</Opcode>", "c448dcca051c75de4cd96c56bd39bcceea2f4936f94b917c5952e3fe3d1fb133")]
    public void Source_valid_optional_metadata_retains_exact_identity(string metadata, string expected)
    {
        var row = Row(metadata);
        Assert.Equal(expected, DirectEventIdentity.Hash(row));
        Assert.Equal(expected, Assert.Single(DirectAdDcPacket.PrepareBatch(new JsonArray(row))).Projection.IdentityHash);
    }
}
