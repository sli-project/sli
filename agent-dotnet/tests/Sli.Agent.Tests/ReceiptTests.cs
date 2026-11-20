using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

/// <summary>Only an exact receipt may delete evidence. The accept/refuse decision is Python's (<c>Spool.acknowledge</c>).</summary>
public class ReceiptTests
{
    [Fact]
    public void ExpiryIsAnExactPermanentRefusalAndNeverDeliveryProof()
    {
        using var key = Helpers.NewKey();
        var packet = Packets.Make(Helpers.Signer(key), Helpers.AgentId, 1, Helpers.Sample("", "1"), Helpers.Now);
        Assert.True(Receipt.IsExpired(packet.Envelope, Helpers.ExpiredReceipt(packet)));
        Assert.False(Receipt.IsDeliveryProof(packet.Envelope, Helpers.ExpiredReceipt(packet)));
        foreach (string field in new[] { "contract_id", "packet_id", "payload_sha256", "status", "error_code", "committed_cursor", "evidence_ref", "committed_at_utc" })
        {
            var bad = Helpers.ExpiredReceipt(packet); bad[field] = "wrong";
            Assert.False(Receipt.IsExpired(packet.Envelope, bad));
            bad.Remove(field);
            Assert.False(Receipt.IsExpired(packet.Envelope, bad));
        }
        var future = Helpers.ExpiredReceipt(packet); future["error_code"] = "agent_replay_window";
        Assert.False(Receipt.IsExpired(packet.Envelope, future));
    }

    public static TheoryData<string> Names()
    {
        var data = new TheoryData<string>();
        foreach (var item in Vectors.Load("receipts.json").AsArray()) data.Add(item!["name"]!.GetValue<string>());
        return data;
    }

    [Theory]
    [MemberData(nameof(Names))]
    public void DecidesLikePython(string name)
    {
        var item = Vectors.Load("receipts.json").AsArray().Single(node => node!["name"]!.GetValue<string>() == name)!.AsObject();
        var envelope = new Envelope(
            item["packet_id"]?.GetValue<string>() ?? "00000000-0000-4000-9000-000000000001", Helpers.AgentId, Helpers.HostId, "sli.heartbeat", "1.0.0", "1",
            "heartbeat", Helpers.HostId, 1, new Cursor("record_id", ""), Cursor.FromJson(item["packet_envelope_cursor_after"] ?? new Cursor("record_id", "1").ToJson()),
            "sli.heartbeat.v1", item["payload_sha256"]?.GetValue<string>() ?? new string('0', 64), 0, 1, Iso8601.Format(Helpers.Now), "not_proven", 0, null);
        Assert.Equal(item["accepted"]!.GetValue<bool>(), Receipt.IsDeliveryProof(envelope, item["receipt"]));
    }

    [Fact]
    public void ExtraKeysInTheCursorAreNotAMatch()
    {
        using var key = Helpers.NewKey();
        var packet = Packets.Make(Helpers.Signer(key), Helpers.AgentId, 1, Helpers.Sample("", "1"), Helpers.Now);
        var receipt = Helpers.Receipt(packet);
        Assert.True(Receipt.IsDeliveryProof(packet.Envelope, receipt));
        receipt["committed_cursor"]!["extra"] = 1;
        Assert.False(Receipt.IsDeliveryProof(packet.Envelope, receipt));
    }

    [Fact]
    public void ReadsTheServerErrorCodeAndStatus()
    {
        var receipt = new JsonObject { ["status"] = "rejected", ["error_code"] = "agent_cursor_mismatch" };
        Assert.Equal("rejected", Receipt.Status(receipt));
        Assert.Equal("agent_cursor_mismatch", Receipt.ErrorCode(receipt));
        Assert.Null(Receipt.Status(JsonValue.Create("oops")));
    }
}
