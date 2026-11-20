using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;
using Sli.Server.Agents.Consumer;
using Xunit;
namespace Sli.Server.Tests.Agents.M4;
public sealed class WorkstationTaskGroupTests
{
    [Fact]
    public void SourceTaskGroupAuditProjectionMatches()
    {
        foreach(var f in Fixture().OfType<JsonObject>()) {
            var actual=Workstation1102Projection.Build(f["packet"]!.AsObject(),f["rows"]!.AsArray(),f["agent_key"]!.GetValue<string>(),23,null);
            var expected=f["observations"]!.AsArray();Assert.Equal(expected.Count,actual.Count);
            for(int i=0;i<actual.Count;i++) {Assert.Equal(expected[i]!["id"]!.GetValue<string>(),actual[i].Id);Assert.Equal(expected[i]!["hash"]!.GetValue<string>(),actual[i].Hash);Assert.True(JsonNode.DeepEquals(expected[i]!["document"],actual[i].Document));}
        }
    }
    private static JsonArray Fixture([CallerFilePath] string path="")=>JsonNode.Parse(File.ReadAllBytes(Path.Combine(Path.GetDirectoryName(path)!,"workstation-task-group.json")))!.AsArray();
}
