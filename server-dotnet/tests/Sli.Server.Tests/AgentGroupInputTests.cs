using System.Text.Json.Nodes;
using Sli.Server.Agents.Groups;
using Sli.Server.Agents.Control;
using Xunit;

namespace Sli.Server.Tests;

public sealed class AgentGroupInputTests
{
    [Fact]
    public void FrozenPythonInputAndDirectoryControlsMatch()
    {
        string fixture="";
        for(var d=new FileInfo(SourcePath()).Directory;d is not null;d=d.Parent)
        {string f=Path.Combine(d.FullName,"server-dotnet/tests/vectors/agent-groups.json");if(File.Exists(f)){fixture=f;break;}}
        var vector=JsonNode.Parse(File.ReadAllBytes(fixture))!;
        Assert.Equal("ddce909d0ddebe43a670e63c85df369e0bd16f17",vector["source_commit"]!.GetValue<string>());
        foreach(var item in vector["cases"]!.AsArray())
        {
            string op=item!["op"]!.GetValue<string>();var input=item["input"];
            object? Run()=>op switch {
                "positive"=>AgentGroupInput.Positive(input),
                "bindings"=>AgentGroupInput.Bindings(input,false),
                "filter"=>AgentGroupInput.Filter(input),
                "onboarding"=>AgentGroupInput.Onboarding(input!.AsObject()),
                "directory"=>AgentGroupDirectory.Record(input,false),
                "directory_ou"=>AgentGroupDirectory.Record(input,true),_=>throw new InvalidOperationException()};
            if(item["error"] is not null)Assert.Equal(item["error"]!.GetValue<string>(),Assert.Throws<AgentControlException>(()=>Run()).Message);
            else
            {
                object? result=Run();
                if(op=="positive")Assert.Equal(item["result"]!.GetValue<long>(),result);
                if(op.StartsWith("directory",StringComparison.Ordinal))Assert.Equal(item["result"]![1]!.AsArray().Select(x=>x!.GetValue<string>()),(string[])result!);
            }
        }
    }
    private static string SourcePath([System.Runtime.CompilerServices.CallerFilePath]string path="")=>path;
    [Fact]
    public void ScopeIdsAreStrictIntegersAndSelectionsAreCanonical()
    {
        Assert.Equal(new long[] { 1, 2 }, AgentGroupInput.Ids(JsonNode.Parse("[2,1,2]"),128));
        foreach (var json in new[] { "true", "1.0", "0", "-1", "9223372036854775808", "\"1\"", "null" })
            Assert.Equal("invalid_group_enrollment_scope", Assert.Throws<AgentControlException>(() => AgentGroupInput.Positive(JsonNode.Parse(json))).Message);
        Assert.Equal(3600, AgentGroupInput.Create(JsonNode.Parse("{\"domain_id\":1,\"max_uses\":2}")!.AsObject()).Ttl);
        Assert.Equal("invalid_enrollment_ttl", Assert.Throws<AgentControlException>(() => AgentGroupInput.Create(JsonNode.Parse("{\"max_uses\":2,\"ttl_seconds\":true}")!.AsObject())).Message);
    }

    [Fact]
    public void AttestationRequiresExactShapeAndUniqueCanonicalRequestIds()
    {
        string id="00000000-0000-0000-0000-000000000001",host="00000000-0000-0000-0000-000000000002";
        var item=JsonNode.Parse($$"""{"request_id":"{{id}}","host_id":"{{host}}","instance_name":null,"key_fingerprint":"{{new string('a',64)}}","computer_entity_id":1}""")!;
        Assert.Single(AgentGroupInput.Bindings(new JsonArray(item.DeepClone()),false));
        Assert.Equal("invalid_agent_batch_evidence",Assert.Throws<AgentControlException>(()=>AgentGroupInput.Bindings(new JsonArray(item.DeepClone(),item.DeepClone()),false)).Message);
        Assert.Empty(AgentGroupInput.Bindings(new JsonArray(),true));
        Assert.Equal("invalid_agent_batch_evidence",Assert.Throws<AgentControlException>(()=>AgentGroupInput.Bindings(new JsonArray(),false)).Message);
        item["computer_entity_id"]=true;
        Assert.Equal("invalid_agent_batch_approval",Assert.Throws<AgentControlException>(()=>AgentGroupInput.Bindings(new JsonArray(item.DeepClone()),true)).Message);
    }

    [Fact]
    public void OnboardingModeDoesNotInventAnImplicitApprovalRule()
    {
        var body=JsonNode.Parse("{\"token_id\":\"00000000000000000000000000000001\",\"template_id\":\"00000000000000000000000000000002\",\"template_version\":1,\"mode\":\"rule\",\"evidence\":[]}")!.AsObject();
        Assert.Null(AgentGroupInput.Onboarding(body).Ids);
        body["request_ids"]=new JsonArray();
        Assert.Equal("invalid_agent_batch_approval",Assert.Throws<AgentControlException>(()=>AgentGroupInput.Onboarding(body)).Message);
        body.Remove("request_ids");body["template_version"]=JsonNode.Parse("1.0");
        Assert.Equal("invalid_agent_template",Assert.Throws<AgentControlException>(()=>AgentGroupInput.Onboarding(body)).Message);
    }
}
