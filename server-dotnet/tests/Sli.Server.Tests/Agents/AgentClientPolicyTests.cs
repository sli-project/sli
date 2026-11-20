using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Server.Agents.ClientControl;
using Sli.Server.Agents.Control;
using Xunit;
namespace Sli.Server.Tests.Agents;
public sealed class AgentClientPolicyTests
{
    [Fact]
    public void Authenticated_version_report_is_retained_without_losing_security_observations()
    {
        var agent=Agent(); agent["rights_probe"]!["identity_conflict"]=new JsonObject { ["computer"]="dc.example.test" };
        var result=AgentClientPolicy.Report(agent,new JsonObject { ["applied_policy_revision"]=4,["collection_state"]="paused",["agent_version"]="1.2.3" },Now);
        Assert.Equal("1.2.3",(string?)result.Probe["agent_version"]);
        Assert.Equal("dc.example.test",(string?)result.Probe["identity_conflict"]?["computer"]);
        Assert.Throws<AgentControlException>(()=>AgentClientPolicy.Report(agent,new JsonObject { ["applied_policy_revision"]=4,["collection_state"]="paused",["agent_version"]="<invalid>" },Now));
    }

    private static JsonObject Agent() => JsonNode.Parse("""
        {"id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","host_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "assigned_modules":[],"policy_revision":4,"applied_policy_revision":2,"applied_collection_state":"active",
        "collection_policy":{"state":"drain"},"rights_probe":{"pending":{"request_id":"cccccccc-cccc-4ccc-8ccc-cccccccccccc"}}}
        """)!.AsObject();
    private static readonly DateTimeOffset Now = new(2026,11,3,1,2,3,TimeSpan.Zero);
    [Fact]
    public void CheckInIsClientParsableAndIncludesInheritedHandoffWithoutPrivateProbeState()
    {
        var agent=Agent();agent["source_host_id"]=agent["host_id"]!.DeepClone();agent["runtime_resume"]=new JsonObject();
        agent["rights_probe"]!["private_diagnostic"]=new JsonObject();
        var wire=AgentClientPolicy.CheckIn(agent,true);
        Assert.Equal("drain",wire["collection_policy"]!["state"]!.GetValue<string>());
        Assert.False(wire["collection_policy"]!.AsObject().ContainsKey("manage_windows_audit"));
        Assert.Equal(agent["host_id"]!.GetValue<string>(),wire["runtime_handoff"]!["source_host_id"]!.GetValue<string>());
        Assert.False(wire.ContainsKey("rights_probe"));Assert.True(wire["delivery_diagnostics_supported"]!.GetValue<bool>());
        wire["collection_policy"]!["state"]="paused";Assert.Equal("drain",agent["collection_policy"]!["state"]!.GetValue<string>());
    }
    [Fact]
    public void ActualClientReportSatisfiesDrainRevisionAndCompatibilityConditions()
    {
        var agent=Agent();var wire=AgentClientPolicy.CheckIn(agent,true);
        // Use the production client report producer rather than manually setting acknowledgement fields.
        var policy=AgentPolicy.Parse(wire,agent["id"]!.GetValue<string>(),EventCatalog.Load());
        var result=AgentClientPolicy.Report(agent,policy.Report("paused","allowed"),Now);
        Assert.Equal(4,result.AppliedRevision);Assert.Equal("paused",result.AppliedState);Assert.True(result.Acknowledged);
        Assert.True(result.Probe["runtime_handoff_supported"]!.GetValue<bool>());Assert.False(result.Probe.ContainsKey("pending"));
        Assert.Equal("allowed",result.ProbeResult!["status"]!.GetValue<string>());
    }
    [Theory]
    [InlineData("{\"applied_policy_revision\":true,\"collection_state\":\"paused\"}","invalid_agent_policy_revision")]
    [InlineData("{\"applied_policy_revision\":5,\"collection_state\":\"paused\"}","invalid_agent_policy_revision")]
    [InlineData("{\"applied_policy_revision\":4.0,\"collection_state\":\"paused\"}","invalid_agent_policy_revision")]
    [InlineData("{\"applied_policy_revision\":4,\"collection_state\":\"active\"}","invalid_agent_collection_state")]
    [InlineData("{\"applied_policy_revision\":4}","invalid_agent_collection_state")]
    [InlineData("{\"applied_policy_revision\":4,\"collection_state\":\"paused\",\"runtime_handoff_supported\":false}","invalid_agent_policy_report")]
    [InlineData("{\"agent_id\":\"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\"}","invalid_agent_policy_report")]
    public void InvalidReportsRetainSourceErrorPrecedence(string json,string code) =>
        Assert.Equal(code,Assert.Throws<AgentControlException>(()=>AgentClientPolicy.Report(Agent(),JsonNode.Parse(json),Now)).Message);
    [Fact]
    public void OlderReportCannotRegressAppliedRevisionOrStateAndDiagnosticsAreNotAcknowledgement()
    {
        var agent=Agent();var old=AgentClientPolicy.Report(agent,JsonNode.Parse("{\"applied_policy_revision\":1,\"collection_state\":\"paused\"}"),Now);
        Assert.Equal(2,old.AppliedRevision);Assert.Null(old.AppliedState);Assert.False(old.Acknowledged);
        var diagnostics=AgentClientPolicy.Report(agent,JsonNode.Parse("{\"delivery_diagnostics\":[]}"),Now);
        Assert.Null(diagnostics.AppliedRevision);Assert.Null(diagnostics.AppliedState);Assert.Single(diagnostics.Output);
    }
    [Fact]
    public void ProbeMismatchAndFutureDiagnosticAreRejectedBeforeAnyMutation()
    {
        var agent=Agent();string original=agent.ToJsonString();
        Assert.Equal("invalid_agent_probe_report",Assert.Throws<AgentControlException>(()=>AgentClientPolicy.Report(agent,
            JsonNode.Parse("{\"applied_policy_revision\":4,\"collection_state\":\"paused\",\"rights_probe\":{\"request_id\":\"wrong\",\"status\":\"allowed\"}}"),Now)).Message);
        Assert.Equal(original,agent.ToJsonString());
        Assert.Equal("invalid_agent_eventlog_diagnostics",Assert.Throws<AgentControlException>(()=>AgentClientPolicy.Report(agent,
            JsonNode.Parse("{\"applied_policy_revision\":4,\"collection_state\":\"paused\",\"eventlog_diagnostics\":[{\"channel\":\"Security\",\"policy_revision\":5,\"observed_at_utc\":\"2026-11-03T00:00:00Z\",\"error\":null}]}"),Now)).Message);
    }
}
