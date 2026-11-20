using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Ingress;
using Sli.Server.Storage.Direct;
using Xunit;

namespace Sli.Server.Tests.Storage;

public class DirectWorkerMixedAdmissionTests
{
    [Theory]
    [InlineData("2026-10-07T00:00:00.1234575Z")]
    [InlineData("2026-10-07T00:00:00.50000050000000000000000000001Z")]
    public void Signed_agent_validator_accepts_mixed_fractional_utc_rows(string time)
    {
        var sample=DirectWorkerMixedDatabaseTests.Sample();var payload=(JsonObject)sample.Packet.DeepClone();
        string xml=$"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><EventRecordID>6</EventRecordID><TimeCreated SystemTime='{time}'/><Channel>Security</Channel><Computer>{DirectWorkerMixedDatabaseTests.Name}</Computer></System><EventData><Data Name='LogonType'>3</Data></EventData></Event>";
        payload["records"]![0]!["record_id"]=6;payload["records"]![0]!["payload"]=EventXml.Parse(xml,DirectWorkerMixedDatabaseTests.Name,"fixture-endpoint","Security");
        var second=xml.Replace("<EventID>4624</EventID>","<EventID>4625</EventID>").Replace("<EventRecordID>6</EventRecordID>","<EventRecordID>7</EventRecordID>");
        payload["records"]!.AsArray().Add(new JsonObject { ["format"]="event_xml",["record_id"]=7,["payload"]=EventXml.Parse(second,DirectWorkerMixedDatabaseTests.Name,"fixture-endpoint","Security") });
        var third=xml.Replace("<EventID>4624</EventID>","<EventID>4634</EventID>").Replace("<EventRecordID>6</EventRecordID>","<EventRecordID>8</EventRecordID>");
        payload["records"]!.AsArray().Add(new JsonObject { ["format"]="event_xml",["record_id"]=8,["payload"]=EventXml.Parse(third,DirectWorkerMixedDatabaseTests.Name,"fixture-endpoint","Security") });
        payload["header"]!["cursor"]!["last_record_id"]=8;payload["header"]!["record_id_range"]!["first"]=6;payload["header"]!["record_id_range"]!["last"]=8;
        var env=(JsonObject)sample.Envelope.DeepClone();env["record_count"]=3;env["payload_sha256"]=Packets.Digest(payload);env["payload_bytes"]=CanonicalJson.Length(payload);
        var state=JsonNode.Parse(env["cursor_after"]!["token"]!.GetValue<string>())!.AsObject();state["channels"]!["Security"]!["record_id"]=8;
        state["channels"]!["Security"]!["bookmark"]=state["channels"]!["Security"]!["bookmark"]!.GetValue<string>().Replace("RecordId='1'","RecordId='8'",StringComparison.Ordinal);env["cursor_after"]!["token"]=CanonicalJson.Serialize(state);
        var rows=AgentAdDcValidator.Validate(Envelope.Parse(env),payload,null,DirectWorkerMixedDatabaseTests.Name);Assert.Equal(3,rows.Count);Assert.Equal(3,DirectAdDcPacket.PrepareBatch(rows).Count);
    }
}
