using System.Text.Json.Nodes;
using System.Text.Json;
using Sli.Server.Agents.Groups;
using Sli.Server.Agents.Control;
using Xunit;

namespace Sli.Server.Tests;

public sealed class AgentTemplatePolicyTests
{
    [Fact]
    public void FrozenPolicyObjectsHashesAndSaveErrorPrecedenceMatch()
    {
        string file="";
        for(var d=new FileInfo(SourcePath()).Directory;d is not null;d=d.Parent){string path=Path.Combine(d.FullName,"server-dotnet/tests/vectors/agent-templates.json");if(File.Exists(path)){file=path;break;}}
        var fixture=JsonNode.Parse(File.ReadAllBytes(file))!;
        Assert.Equal("ddce909d0ddebe43a670e63c85df369e0bd16f17",fixture["source_commit"]!.GetValue<string>());
        foreach(var c in fixture["policies"]!.AsArray())
        {
            if(c!["error"] is not null)Assert.Equal(c["error"]!.GetValue<string>(),Assert.Throws<AgentControlException>(()=>AgentTemplatePolicy.Normalize(c["modules"],c["control"])).Message);
            else
            {
                var policy=AgentTemplatePolicy.Normalize(c["modules"],c["control"]);
                Assert.True(JsonNode.DeepEquals(c["result"],policy),c["name"]!.GetValue<string>());
                Assert.Equal(c["sha256"]!.GetValue<string>(),AgentTemplatePolicy.Hash(policy));
            }
        }
        foreach(var c in fixture["bodies"]!.AsArray())
        {
            var input=JsonSerializer.SerializeToElement(c!["body"]);
            if(c["sql_calls"]!.GetValue<int>()==0)Assert.Equal(c["error"]!.GetValue<string>(),Assert.Throws<AgentControlException>(()=>AgentTemplateService.Prepare(input)).Message);
            else Assert.NotNull(AgentTemplateService.Prepare(input).Policy); // SQL/version phase is later, not a simulated DB PASS.
        }
    }
    private static string SourcePath([System.Runtime.CompilerServices.CallerFilePath]string path="")=>path;
    [Fact]
    public void NativeProducerNormalizesPortableConfigAndForcesPersonalRevision()
    {
        var module=new JsonArray(new JsonObject{["module_id"]="sli.workstations",["enabled"]=false,["config"]=new JsonObject{["policy_revision"]=null,["allow_process_paths"]=new JsonArray("C:\\Straße\\*")}});
        var policy=AgentTemplatePolicy.Normalize(module,new JsonObject{["state"]="drain"});
        Assert.Equal("1",policy["assigned_modules"]![0]!["config"]!["policy_revision"]!.GetValue<string>());
        Assert.Equal("c:/strasse/*",policy["assigned_modules"]![0]!["config"]!["allow_process_paths"]![0]!.GetValue<string>());
        Assert.Equal("drain",policy["collection_policy"]!["state"]!.GetValue<string>());
        Assert.Equal(60,policy["collection_policy"]!["interval_seconds"]!.GetValue<int>());
    }
    [Fact]
    public void TemplatesRejectSourceBoundModulesAndInvalidDisabledConfig()
    {
        foreach(string id in new[]{"sli.file-audit","sli.windows.ad-dc","sli.heartbeat","unknown"})
            Assert.Equal("invalid_agent_template",Assert.Throws<AgentControlException>(()=>AgentTemplatePolicy.Normalize(new JsonArray(new JsonObject{["module_id"]=id,["enabled"]=true,["config"]=new JsonObject()}),new JsonObject())).Message);
        var modules=JsonNode.Parse("[{\"module_id\":\"sli.workstations\",\"enabled\":false,\"config\":{\"deny_event_ids\":null}}]");
        Assert.Equal("invalid_agent_template",Assert.Throws<AgentControlException>(()=>AgentTemplatePolicy.Normalize(modules,new JsonObject())).Message);
    }
}
