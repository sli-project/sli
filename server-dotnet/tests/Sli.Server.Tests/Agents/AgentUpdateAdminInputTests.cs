using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Updates;
using Xunit;
namespace Sli.Server.Tests.Agents;
public sealed class AgentUpdateAdminInputTests
{
    [Fact]
    public void SourceWaveSelectionAndDuplicateRulesMatch()
    {
        var fixture=Fixture();foreach(var item in fixture["cases"]!.AsArray()) {
            using var body=JsonDocument.Parse(item!["raw"]!.GetValue<string>());
            if(item["error"] is not null)Assert.Equal(item["error"]!.GetValue<string>(),Assert.Throws<AgentControlException>(()=>AgentUpdateAdminInput.Wave(body.RootElement)).Message);
            else {
                var value=AgentUpdateAdminInput.Wave(body.RootElement);var expected=item["output"]!;
                Assert.Equal(expected["sha256"]!.GetValue<string>(),value.Sha256);Assert.Equal(expected["batch_size"]!.GetValue<int>(),value.BatchSize);Assert.Equal(expected["error_threshold"]!.GetValue<int>(),value.Threshold);
                Assert.Equal(expected["group_token_id"]?.GetValue<string>(),value.Group?.ToString("D"));
                Assert.Equal(expected["agent_ids"]?.AsArray().Select(x=>x!.GetValue<string>()).ToArray(),value.Ids?.Select(x=>x.ToString("D")).ToArray());
            }
        }
    }
    [Fact]
    public void SourceWaveListQueryDropsBlankButNeverWidensUnknownParameters()
    {
        Assert.Null(AgentUpdateAdminInput.WaveQuery("?wave_id=&ignored="));
        Assert.Equal("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",AgentUpdateAdminInput.WaveQuery("?wave_id={aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa}")!.Value.ToString("D"));
        foreach(string query in new[]{"?other=1","?Wave_id=x","?wave_id=x&wave_id=y"})Assert.Equal("agent_update_wave_invalid",Assert.Throws<AgentControlException>(()=>AgentUpdateAdminInput.WaveQuery(query)).Message);
        Assert.Equal("invalid_agent_identity",Assert.Throws<AgentControlException>(()=>AgentUpdateAdminInput.WaveQuery("?wave_id=x")).Message);
    }
    private static JsonNode Fixture([System.Runtime.CompilerServices.CallerFilePath]string path="")
    {for(var d=new FileInfo(path).Directory;d is not null;d=d.Parent){string f=Path.Combine(d.FullName,"server-dotnet/tests/vectors/agent-update-admin.json");if(File.Exists(f))return JsonNode.Parse(File.ReadAllBytes(f))!;}throw new IOException();}
}
