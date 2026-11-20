using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;
using Sli.Server.Agents.Consumer;
using Sli.Agent.Core;
using Xunit;
namespace Sli.Server.Tests.Agents.M4;
public sealed class WorkstationLogonsTests
{
    [Fact]
    public void SourceLogonProjectionAndHashesMatch()
    {
        foreach(var f in Fixture().OfType<JsonObject>()) {
            var actual=Workstation1102Projection.Build(f["packet"]!.AsObject(),f["rows"]!.AsArray(),f["agent_key"]!.GetValue<string>(),23,null);
            var expected=f["observations"]!.AsArray();Assert.Equal(expected.Count,actual.Count);
            for(int i=0;i<actual.Count;i++) {Assert.Equal(expected[i]!["id"]!.GetValue<string>(),actual[i].Id);Assert.Equal(expected[i]!["hash"]!.GetValue<string>(),actual[i].Hash);Assert.True(JsonNode.DeepEquals(expected[i]!["document"],actual[i].Document));}
        }
    }
    [Fact]
    public void UnknownMemberIsIgnoredAndInvalidContextIsRejected()
    {
        var f=Fixture()[0]!.AsObject(); var packet=f["packet"]!.AsObject();var rows=f["rows"]!.AsArray();string host=f["agent_key"]!.GetValue<string>();
        var changed=(JsonObject)packet.DeepClone(); var changedRows=(JsonArray)rows.DeepClone();
        string xml=changed["records"]![1]!["payload"]!["xml"]!.GetValue<string>().Replace("<EventID>4625</EventID>","<EventID>9999</EventID>");
        var row=EventXml.Parse(xml,host,"","Security");changed["records"]![1]!["payload"]=row.DeepClone();changedRows[1]=row;
        var imported=Workstation1102Projection.Build(changed,changedRows,host,23,null);
        Assert.Equal(Workstation1102Projection.Build(packet,rows,host,23,null).Count-1,imported.Count);
        Assert.DoesNotContain(imported,x=>x.Document["event_id"]!.GetValue<int>()==9999);
        changed=(JsonObject)packet.DeepClone(); changed["context"]!["workstations"]=new JsonObject{["protection_state"]=new JsonObject()};
        var error=Assert.Throws<InvalidDataException>(()=>Workstation1102Projection.Build(changed,rows,host,23,null));
        Assert.Equal("workstation_protection_state_invalid",error.Message);
        var withAd=Workstation1102Projection.Build(packet,rows,host,23,42);Assert.All(withAd,x=>Assert.Equal("available",x.Document["quality"]!["ad_enrichment"]!.GetValue<string>()));
    }
    private static JsonArray Fixture([CallerFilePath] string path="")=>JsonNode.Parse(File.ReadAllBytes(Path.Combine(Path.GetDirectoryName(path)!,"workstation-logons.json")))!.AsArray();
}
