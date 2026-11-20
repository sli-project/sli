using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;
using Sli.Server.Agents.Consumer;
using Xunit;
namespace Sli.Server.Tests.Agents.M4;
public sealed class WorkstationSignatureTests
{
    [Fact]
    public void SourceSignatureBindingsAndObservationsMatch()
    {
        foreach(var f in Fixture()["positive"]!.AsArray().OfType<JsonObject>()) {
            var actual=Workstation1102Projection.Build(f["packet"]!.AsObject(),f["rows"]!.AsArray(),f["agent_key"]!.GetValue<string>(),23,null);
            var expected=f["observations"]!.AsArray();Assert.Equal(expected.Count,actual.Count);
            for(int i=0;i<actual.Count;i++){Assert.Equal(expected[i]!["id"]!.GetValue<string>(),actual[i].Id);Assert.Equal(expected[i]!["hash"]!.GetValue<string>(),actual[i].Hash);Assert.True(JsonNode.DeepEquals(expected[i]!["document"],actual[i].Document));Assert.Equal(f["rows"]![i]!["xml"]!.GetValue<string>(),actual[i].SourceXml);}
        }
    }
    [Fact]
    public void InvalidBindingsFailWholePacket()
    {
        var fixture=Fixture();var host=fixture["positive"]![0]!["agent_key"]!.GetValue<string>();
        foreach(var f in fixture["negative"]!.AsArray().OfType<JsonObject>()) {
            Assert.False(f["accepted"]!.GetValue<bool>());
            Assert.Throws<InvalidDataException>(()=>Workstation1102Projection.Build(f["packet"]!.AsObject(),f["rows"]!.AsArray(),host,23,null));
        }
    }
    private static JsonObject Fixture([CallerFilePath]string path="")=>JsonNode.Parse(File.ReadAllBytes(Path.Combine(Path.GetDirectoryName(path)!,"workstation-signatures.json")))!.AsObject();
}
