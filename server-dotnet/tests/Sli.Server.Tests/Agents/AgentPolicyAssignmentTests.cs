using System.Text.Json.Nodes;
using Sli.Server.Agents.Ingress;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class AgentPolicyAssignmentTests
{
    [Fact]
    public void CurrentAssignmentRequiresExactlyOneEnabledObject()
    {
        var assignments=JsonNode.Parse("""[{"module_id":"sli.file-audit","enabled":true,"config":{"policy_revision":"3"}}]""")!.AsArray();
        Assert.Equal("3",AgentPolicyAssignments.FindCurrent(assignments,"sli.file-audit")!["config"]!["policy_revision"]!.GetValue<string>());
        assignments.Add(JsonNode.Parse("""{"module_id":"sli.file-audit","enabled":false}"""));
        Assert.Null(AgentPolicyAssignments.FindCurrent(assignments,"sli.file-audit"));
        Assert.Null(AgentPolicyAssignments.FindCurrent(JsonNode.Parse("""[{"module_id":"sli.file-audit","enabled":false}]""")!.AsArray(),"sli.file-audit"));
    }

    [Fact]
    public void RevisionMustBeSourceExactAndHistoricalCandidateIsBounded()
    {
        var empty=JsonNode.Parse("""{"module_id":"sli.file-audit","enabled":true,"config":{}}""")!.AsObject();
        Assert.True(AgentPolicyAssignments.MatchesRevision(empty,"1"));
        Assert.False(AgentPolicyAssignments.MatchesRevision(empty,"01"));
        empty["config"]!["policy_revision"]=3;
        Assert.False(AgentPolicyAssignments.MatchesRevision(empty,"3"));
        Assert.True(AgentPolicyAssignments.ValidHistoryRevision("9007199254740991"));
        Assert.False(AgentPolicyAssignments.ValidHistoryRevision("9007199254740992"));
        Assert.False(AgentPolicyAssignments.ValidHistoryRevision("٠١"));
        Assert.False(AgentPolicyAssignments.ValidHistoryRevision("0"));
    }
}
