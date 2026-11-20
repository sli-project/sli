using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;
using Sli.Server.Agents.Consumer;
using Xunit;
namespace Sli.Server.Tests.Agents.M4;
public sealed class WorkstationScriptTests
{
    [Fact]
    public void SourceScriptMaskAndHashMatch()
    {
        foreach(var f in Fixture().OfType<JsonObject>()) {
            var actual=Workstation1102Projection.Build(f["packet"]!.AsObject(),f["rows"]!.AsArray(),f["agent_key"]!.GetValue<string>(),23,null);
            var expected=f["observations"]!.AsArray();Assert.Equal(expected.Count,actual.Count);
            for(int i=0;i<actual.Count;i++) {Assert.Equal(expected[i]!["id"]!.GetValue<string>(),actual[i].Id);Assert.Equal(expected[i]!["hash"]!.GetValue<string>(),actual[i].Hash);Assert.True(JsonNode.DeepEquals(expected[i]!["document"],actual[i].Document));Assert.Equal(f["rows"]![i]!["xml"]!.GetValue<string>(),actual[i].SourceXml);}
            Assert.DoesNotContain("synthetic123",actual[0].Document["facts"]!["script_block_text"]!.GetValue<string>());
            Assert.DoesNotContain("synthetic123",actual[2].Document["facts"]!["script_block_text"]!.GetValue<string>());
        }
    }
    private static JsonArray Fixture([CallerFilePath] string path="")=>JsonNode.Parse(File.ReadAllBytes(Path.Combine(Path.GetDirectoryName(path)!,"workstation-script.json")))!.AsArray();
}
