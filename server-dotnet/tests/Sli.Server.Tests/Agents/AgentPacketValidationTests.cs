using System.Text.Json.Nodes;
using Sli.Server.Agents.Ingress;
using Sli.Agent.Protocol;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class AgentPacketValidationTests
{
    [Fact]
    public void HeartbeatMatchesSourceIdentityAndShape()
    {
        var agent = Guid.Parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        var payload = JsonNode.Parse("""{"contract":"sli.heartbeat.v1","status":"alive"}""")!.AsObject();
        Assert.True(HeartbeatValidator.IsValid(agent, "heartbeat", agent.ToString(), "1.0.0", "1", payload, "not_proven", 0, null));
        payload["status"] = "bad";
        Assert.False(HeartbeatValidator.IsValid(agent, "heartbeat", agent.ToString(), "1.0.0", "1", payload, "not_proven", 0, null));
    }
    [Fact]
    public void EventLogRowsPreserveSourceAndRejectCursorAndBindingMismatch()
    {
        var now = DateTimeOffset.Parse("2026-10-07T12:00:00+00:00");
        var row = new JsonObject { ["record_id"] = 5, ["xml"] = "<Event />", ["computer_name"] = "dc.example", ["channel"] = "Security" };
        var payload = CollectionPacket.Make("dc.example", "Security", "generation", new JsonObject { ["after_record_id"] = null, ["last_record_id"] = 5 },
            [new PacketRecord("event_xml", 5, row)], "not_proven", null, now);
        var envelope = new Envelope("00000000-0000-4000-8000-000000000001", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "host", "sli.windows-eventlog", "1.0.0", "1", "Security", "generation", 1,
            new Cursor("record_id", ""), new Cursor("record_id", "5"), CollectionPacket.Contract, Packets.Digest(payload), 1, CanonicalJson.Length(payload), Iso8601.Format(now), "not_proven", 0, null);
        var rows=EventLogValidator.Validate(envelope,payload,"dc.example");
        Assert.True(JsonNode.DeepEquals(row,rows[0]));
        Assert.Equal("agent_collection_packet_invalid", Assert.Throws<ProtocolException>(() => EventLogValidator.Validate(envelope,payload,"wrong-source")).Code);
        Assert.Equal("agent_collection_packet_invalid", Assert.Throws<ProtocolException>(() => EventLogValidator.Validate(envelope with { CursorAfter = new Cursor("record_id", "6") },payload,"dc.example")).Code);
        // A header cursor boolean may compare numerically, but a payload row ID must be a JSON integer.
        var boolRow = new JsonObject { ["record_id"] = true, ["xml"] = "<Event />", ["computer_name"] = "dc.example", ["channel"] = "Security" };
        var boolPayload = CollectionPacket.Make("dc.example", "Security", "generation", new JsonObject { ["after_record_id"] = null, ["last_record_id"] = true },
            [new PacketRecord("event_xml", 1, boolRow)], "not_proven", null, now);
        var boolEnvelope = envelope with { CursorAfter = new Cursor("record_id", "1") };
        Assert.Equal("agent_collection_packet_invalid", Assert.Throws<ProtocolException>(() => EventLogValidator.Validate(boolEnvelope, boolPayload, "dc.example")).Code);
        payload["records"]![0]!["payload"]!["record_id"] = 6;
        Assert.Equal("agent_collection_packet_invalid", Assert.Throws<ProtocolException>(() => EventLogValidator.Validate(envelope,payload,"dc.example")).Code);
    }
    [Theory]
    [InlineData("5", "5.0", true)]
    [InlineData("5", "5e0", true)]
    [InlineData("5.0", "5", false)]
    [InlineData("true", "true", false)]
    [InlineData("1", "true", true)]
    [InlineData("9007199254740993", "9007199254740992.0", false)]
    public void Source_numeric_rules_distinguish_row_ids_from_header_cursor(string rowId, string headerId, bool accepted)
    {
        var now = DateTimeOffset.Parse("2026-10-07T12:00:00+00:00");
        var outer = rowId is "true" or "1" ? System.Numerics.BigInteger.One : System.Numerics.BigInteger.Parse(rowId == "5.0" ? "5" : rowId);
        var row = new JsonObject { ["record_id"] = JsonNode.Parse(rowId), ["xml"] = "<Event />", ["computer_name"] = "dc.example", ["channel"] = "Security" };
        var payload = CollectionPacket.Make("dc.example", "Security", "generation", new JsonObject { ["after_record_id"] = null, ["last_record_id"] = JsonNode.Parse(headerId) },
            [new PacketRecord("event_xml", outer, row)], "not_proven", null, now);
        var envelope = new Envelope("00000000-0000-4000-8000-000000000001", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "host", "sli.windows-eventlog", "1.0.0", "1", "Security", "generation", 1,
            new Cursor("record_id", ""), new Cursor("record_id", outer.ToString()), CollectionPacket.Contract, Packets.Digest(payload), 1, CanonicalJson.Length(payload), Iso8601.Format(now), "not_proven", 0, null);
        if (accepted) Assert.Single(EventLogValidator.Validate(envelope,payload,"dc.example"));
        else Assert.Equal("agent_collection_packet_invalid", Assert.Throws<ProtocolException>(() => EventLogValidator.Validate(envelope,payload,"dc.example")).Code);
    }
}
