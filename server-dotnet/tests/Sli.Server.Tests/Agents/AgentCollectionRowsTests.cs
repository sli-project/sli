using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Ingress;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class AgentCollectionRowsTests
{
    [Fact]
    public void EventRowsAreBoundToHeaderAndRetainEvidence()
    {
        var now=DateTimeOffset.Parse("2026-10-07T12:00:00+00:00");
        var row=new JsonObject { ["record_id"]=7,["xml"]="<Event/>",["computer_name"]="fixture-host",["channel"]="Security",["extra"]="keep" };
        var payload=CollectionPacket.Make("fixture-host","Security","generation",new JsonObject(),[new PacketRecord("event_xml",7,row)],"not_proven",null,now);
        var result=AgentCollectionRows.ExtractEvents(payload);
        Assert.True(JsonNode.DeepEquals(row,result[0]));
        result[0]!["extra"]="changed"; Assert.Equal("keep",payload["records"]![0]!["payload"]!["extra"]!.GetValue<string>());
        payload["records"]![0]!["payload"]!["record_id"]=7.0; Assert.Single(AgentCollectionRows.ExtractEvents(payload));
        payload["records"]![0]!["record_id"]=1; payload["header"]!["record_id_range"]!["first"]=1; payload["header"]!["record_id_range"]!["last"]=1; payload["records"]![0]!["payload"]!["record_id"]=true; Assert.Single(AgentCollectionRows.ExtractEvents(payload));
        payload["records"]![0]!["payload"]!["computer_name"]="other-host";
        Assert.Throws<ProtocolException>(()=>AgentCollectionRows.ExtractEvents(payload));
    }

    [Fact]
    public void RejectsAccountingAndMissingRecordIdentity()
    {
        var now=DateTimeOffset.Parse("2026-10-07T12:00:00+00:00");
        var payload=CollectionPacket.Make("fixture-host","Security","generation",new JsonObject(),[new PacketRecord("accounting_line",null,JsonValue.Create("line")!)],"not_proven",null,now);
        Assert.Throws<ProtocolException>(()=>AgentCollectionRows.ExtractEvents(payload));
    }
}


