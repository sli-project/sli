using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Consumer;
using Xunit;
namespace Sli.Server.Tests.Agents.M4;
public sealed class WorkstationProtectionTests
{
    [Fact]
    public void SourceStateOnlyAndMixedPacketsMatch()
    {
        foreach(var f in Fixture()["positive"]!.AsArray().OfType<JsonObject>()) {
            var actual=Workstation1102Projection.Build(f["packet"]!.AsObject(),f["rows"]!.AsArray(),f["agent_key"]!.GetValue<string>(),23,null);
            var expected=f["observations"]!.AsArray();Assert.Equal(expected.Count,actual.Count);
            for(int i=0;i<actual.Count;i++){Assert.Equal(expected[i]!["id"]!.GetValue<string>(),actual[i].Id);Assert.Equal(expected[i]!["hash"]!.GetValue<string>(),actual[i].Hash);Assert.True(JsonNode.DeepEquals(expected[i]!["document"],actual[i].Document));}
            var state=f["packet"]!["context"]!["workstations"]!["protection_state"]!;
            Assert.Equal(f["state_hash"]!.GetValue<string>(),Packets.Digest(state));Assert.Equal(f["state_id"]!.GetValue<string>(),Packets.Digest(new JsonArray(f["agent_key"]!.DeepClone(),JsonValue.Create("protection_state"))));
        }
    }
    [Fact]
    public void InvalidProtectionIsRejectedAndEmptyPacketsAreIgnored()
    {
        var f=Fixture();string host=f["positive"]![0]!["agent_key"]!.GetValue<string>();
        foreach(var row in f["negative"]!.AsArray().OfType<JsonObject>()) {Assert.False(row["accepted"]!.GetValue<bool>());Assert.Throws<InvalidDataException>(()=>Workstation1102Projection.Build(row["packet"]!.AsObject(),new JsonArray(),host,23,null));}
        var empty=(JsonObject)f["positive"]![0]!["packet"]!.DeepClone();empty["context"]!["workstations"]!.AsObject().Remove("protection_state");
        Assert.Empty(Workstation1102Projection.Build(empty,new JsonArray(),host,23,null));
    }
    private static JsonObject Fixture([CallerFilePath]string path="")=>JsonNode.Parse(File.ReadAllBytes(Path.Combine(Path.GetDirectoryName(path)!,"workstation-protection.json")))!.AsObject();
}
