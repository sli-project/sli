using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;
using Sli.Server.Agents.Consumer;
using Sli.Agent.Core;
using Xunit;

namespace Sli.Server.Tests.Agents.M4;
public sealed class Workstation1102ProjectionTests
{
    private static JsonObject Fixture([CallerFilePath] string path="")=>JsonNode.Parse(File.ReadAllBytes(Path.Combine(Path.GetDirectoryName(path)!,"workstation-1102.json")))!.AsObject();
    [Fact]
    public void SourceObservationAndHashesMatch()
    {
        var f=Fixture(); var results=Workstation1102Projection.Build(f["packet"]!.AsObject(),f["rows"]!.AsArray(),f["agent_key"]!.GetValue<string>(),23,null);
        var item=Assert.Single(results); Assert.Equal(f["observation_id"]!.GetValue<string>(),item.Id); Assert.Equal(f["observation_sha256"]!.GetValue<string>(),item.Hash);
        Assert.True(JsonNode.DeepEquals(f["observation"],item.Document));
        var equivalent=(JsonArray)f["rows"]!.DeepClone();equivalent[0]!["event_id"]=JsonNode.Parse("1102.0");
        Assert.Equal(item.Id,Assert.Single(Workstation1102Projection.Build(f["packet"]!.AsObject(),equivalent,f["agent_key"]!.GetValue<string>(),23,null)).Id);
    }
    [Fact]
    public void UnknownEvidenceIsIgnoredAndInvalidExtensionsAreRejected()
    {
        var f=Fixture(); var packet=f["packet"]!.AsObject();var rows=f["rows"]!.AsArray();
        var other=(JsonObject)packet.DeepClone(); string xml=other["records"]![0]!["payload"]!["xml"]!.GetValue<string>().Replace("<EventID>1102</EventID>","<EventID>9999</EventID>");
        var changed=EventXml.Parse(xml,f["agent_key"]!.GetValue<string>(),"","Security"); other["records"]![0]!["payload"]=changed.DeepClone();
        Assert.Empty(Workstation1102Projection.Build(other,new JsonArray(changed),f["agent_key"]!.GetValue<string>(),23,null));
        other=(JsonObject)packet.DeepClone(); other["context"]!["workstations"]=new JsonObject { ["protection_state"]=new JsonObject() };
        var error=Assert.Throws<InvalidDataException>(()=>Workstation1102Projection.Build(other,rows,f["agent_key"]!.GetValue<string>(),23,null));
        Assert.Equal("workstation_protection_state_invalid",error.Message);
    }
}


