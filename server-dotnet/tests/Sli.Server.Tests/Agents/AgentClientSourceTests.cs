using System.Text.Json.Nodes;
using Sli.Server.Agents.ClientControl;
using Sli.Server.Agents.Control;
using Xunit;
namespace Sli.Server.Tests.Agents;
public sealed class AgentClientSourceTests
{
    [Fact]
    public void FrozenPythonWireAndErrorsMatchIncludingSourceDiagnosticTimestamps()
    {
        var fixture=JsonNode.Parse(File.ReadAllBytes(Vector()))!.AsObject();Assert.Equal("ddce909d0ddebe43a670e63c85df369e0bd16f17",fixture["source_commit"]!.GetValue<string>());
        var now=new DateTimeOffset(2026,11,3,1,2,3,TimeSpan.Zero);
        Assert.Equal(14,fixture["reports"]!.AsArray().Count);Assert.Equal(4,fixture["checkins"]!.AsArray().Count);
        foreach(var item in fixture["reports"]!.AsArray()) {
            if(item!["error"] is not null)Assert.Equal(item["error"]!.GetValue<string>(),Assert.Throws<AgentControlException>(()=>AgentClientPolicy.Report(item["agent"]!.AsObject(),item["body"],now)).Message);
            else Assert.True(JsonNode.DeepEquals(item["output"],AgentClientPolicy.Report(item["agent"]!.AsObject(),item["body"],now).Output),item["name"]!.GetValue<string>());
        }
        foreach(var item in fixture["checkins"]!.AsArray())Assert.True(JsonNode.DeepEquals(item!["output"],AgentClientPolicy.CheckIn(item["agent"]!.AsObject(),true)),item["name"]!.GetValue<string>());
    }
    private static string Vector([System.Runtime.CompilerServices.CallerFilePath] string path="")
    { for(var d=new FileInfo(path).Directory;d is not null;d=d.Parent){string f=Path.Combine(d.FullName,"server-dotnet/tests/vectors/agent-client-control.json");if(File.Exists(f))return f;}throw new IOException(); }
}
