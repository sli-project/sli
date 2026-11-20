using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;
using Sli.Server.Agents.Consumer;
using Xunit;

namespace Sli.Server.Tests.Agents.M4;
public sealed class WorkstationServiceDefenderTests
{
    [Fact]
    public void SourceMixedPacketsAndHashesMatch()
    {
        var file=Path.Combine(Path.GetDirectoryName(SourcePath())!,"workstation-service-defender.json");
        foreach(var f in JsonNode.Parse(File.ReadAllBytes(file))!.AsArray().OfType<JsonObject>()) {
            var actual=Workstation1102Projection.Build(f["packet"]!.AsObject(),f["rows"]!.AsArray(),f["agent_key"]!.GetValue<string>(),23,42);
            var expected=f["observations"]!.AsArray(); Assert.Equal(expected.Count,actual.Count);
            for(int i=0;i<actual.Count;i++) { Assert.Equal(expected[i]!["id"]!.GetValue<string>(),actual[i].Id);Assert.Equal(expected[i]!["hash"]!.GetValue<string>(),actual[i].Hash);Assert.True(JsonNode.DeepEquals(expected[i]!["document"],actual[i].Document)); }
        }
    }
    private static string SourcePath([CallerFilePath] string path="")=>path;
}
