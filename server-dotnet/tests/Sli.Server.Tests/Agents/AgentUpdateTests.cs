using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Agents.ClientControl;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Updates;
using Xunit;
namespace Sli.Server.Tests.Agents;
public sealed class AgentUpdateTests
{
    [Fact]
    public void FrozenSourceInputErrorsAndRolloutDecisionsMatch()
    {
        var fixture=JsonNode.Parse(File.ReadAllBytes(Vector()))!;
        Assert.Equal("ddce909d0ddebe43a670e63c85df369e0bd16f17",fixture["source_commit"]!.GetValue<string>());
        foreach(var item in fixture["reports"]!.AsArray()) {
            using var document=JsonDocument.Parse(item!["raw"]!.GetValue<string>());
            var body=AgentClientJson.FromElement(document.RootElement)!.AsObject();
            if(item["error"] is not null)Assert.Equal(item["error"]!.GetValue<string>(),Assert.Throws<AgentControlException>(()=>AgentUpdateInput.Parse(body)).Message);
            else {
                var value=AgentUpdateInput.Parse(body);
                Assert.Equal(body["sha256"]!.GetValue<string>(),value.Sha256);Assert.Equal(body["version"]!.GetValue<string>(),value.Version);
                Assert.Equal(body["status"]!.GetValue<string>(),value.Status);Assert.Equal(body["reason"]?.GetValue<string>(),value.Reason);
            }
        }
        foreach(var item in fixture["waves"]!.AsArray()) {
            var members=item!["members"]!.AsArray().Select(m=>new AgentUpdateMember(Guid.Empty,m!["batch_number"]!.GetValue<int>(),m["state"]!.GetValue<string>(),m["had_error"]!.GetValue<bool>(),m["agent_status"]!.GetValue<string>())).ToArray();
            var plan=AgentUpdateWaves.Decide(members,item["current_batch"]!.GetValue<int>(),item["error_threshold"]!.GetValue<int>());
            Assert.Equal(item["action"]!.GetValue<string>(),plan.Action);Assert.Equal(item["reason"]?.GetValue<string>(),plan.Reason);Assert.Equal(item["errors"]!.GetValue<int>(),plan.Errors);
        }
    }
    [Fact]
    public void QueryMatchesSourceBlankAndMultiplicityRulesWithCaseSensitiveKeys()
    {
        string sha=new('a',64);
        foreach(var query in new[]{"?sha256="+sha,"?ignored=&sha256=&sha256="+sha,"?%73ha256="+sha})Assert.Equal(sha,AgentUpdateInput.PackageQuery(query));
        foreach(var query in new[]{"","?sha256=","?Sha256="+sha,"?sha256="+sha+"&sha256="+sha,"?sha256="+sha+"&extra=1","?sha256="+new string('A',64),"?sha256="+sha+"%0A"})
            Assert.Equal("agent_package_invalid",Assert.Throws<AgentControlException>(()=>AgentUpdateInput.PackageQuery(query)).Message);
    }
    private static string Vector([System.Runtime.CompilerServices.CallerFilePath]string path="")
    {for(var d=new FileInfo(path).Directory;d is not null;d=d.Parent){string f=Path.Combine(d.FullName,"server-dotnet/tests/vectors/agent-update.json");if(File.Exists(f))return f;}throw new IOException();}
}
