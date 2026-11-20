using System.Text.Json;
using Sli.Server.Access;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Diagnostics;
using Xunit;
namespace Sli.Server.Tests.Agents;

public sealed class WorkstationAgentScopeTests
{
    private static AccessFacts Facts(params JsonElement[] policies)=>new(false,"operator",[],[],policies,[],[],[],[]);
    private static AtomicReportGrant Grant(string scope,params string[] fields)=>new(JsonSerializer.Deserialize<JsonElement>(scope),fields.ToHashSet(),new HashSet<string>{"view"},1,1);
    private static readonly string[] Fields=["identity_basic","technical","security","privilege"];
    private static AccessDecision Access(CapabilityDecisionSet caps,params ReportDecision[] reports)=>new("operator",caps,reports);
    [Fact]
    public void FleetQueryKeepsSourceSingleUuidAndBlankQuerySemantics()
    {
        var id="aabbccdd-1234-4234-8234-001122334455";
        Assert.Equal((id,id),WorkstationAgentReader.Validate("?agent_key="+id+"&cursor="+id));
        Assert.Equal((null,null),WorkstationAgentReader.Validate("?agent_key=&cursor=&unknown="));
        foreach(string raw in new[]{"?unknown=x","?cursor=bad","?agent_key="+id+"&agent_key="+id,"?cursor=1"})
            Assert.Equal("workstation_request_invalid",Assert.Throws<AgentControlException>(()=>WorkstationAgentReader.Validate(raw)).Message);
    }    [Fact]
    public void AtomicFieldsLegacyAndCurrentCapabilitiesRetainIndependentDenies()
    {
        var f=Facts();var caps=new CapabilityComposer().Compose(f);
        var legacy=new ReportDecision("workstations.logons",true,[Grant("{\"kind\":\"all\"}",Fields)]);
        Assert.Contains("TRUE",WorkstationAgentScope.Build(f,Access(caps,legacy)).Sql);
        var current=legacy with{ReportKey="workstations.overview"};
        Assert.Contains("FALSE",WorkstationAgentScope.Build(f,Access(caps,current)).Sql);
        var split=legacy with{Grants=[Grant("{\"kind\":\"all\"}","identity_basic","technical"),Grant("{\"kind\":\"all\"}","security","privilege")]};
        Assert.Equal("workstation_access_denied",Assert.Throws<AgentControlException>(()=>WorkstationAgentScope.Build(f,Access(caps,split))).Message);
        var deny=JsonSerializer.SerializeToElement(new{capability_key="workstations.read",effect="deny",scope_json=new{kind="domain",ids=new[]{7}}});
        f=Facts(deny);caps=new CapabilityComposer().Compose(f);
        var predicate=WorkstationAgentScope.Build(f,Access(caps,legacy));Assert.Contains("NOT",predicate.Sql);Assert.Contains("r.collection_scope_id",predicate.Sql);
        Assert.Contains(predicate.Parameters,p=>p.Value is string[] a&&a.Contains("ad-domain:7"));
        var invalid=JsonSerializer.SerializeToElement(new{capability_key="workstations.read",effect="deny",scope_json=new{kind="unknown"}});
        f=Facts(invalid);caps=new CapabilityComposer().Compose(f);Assert.Contains("FALSE",WorkstationAgentScope.Build(f,Access(caps,legacy)).Sql);
    }
    [Fact]
    public void AgentOuAndGenericClausesAreParameterizedAndInvalidNeverWidens()
    {
        var f=Facts();var c=new CapabilityComposer().Compose(f);
        foreach(string scope in new[]{"{\"kind\":\"agent\",\"ids\":[\"opaque-agent-key\"]}","{\"kind\":\"ou\",\"domain_id\":7,\"values\":[\"OU=Bound\"]}","{\"mode\":\"restricted\",\"clauses\":[{\"plugin_ids\":[\"sli.workstations\"],\"entity_ids\":[7]}]}"})
        {
            var p=WorkstationAgentScope.Build(f,Access(c,new ReportDecision("workstations.usb",true,[Grant(scope,Fields)])));
            Assert.NotEmpty(p.Parameters);Assert.DoesNotContain("opaque-agent-key",p.Sql);Assert.DoesNotContain("OU=Bound",p.Sql);
        }
        foreach(string scope in new[]{"{}","{\"kind\":\"all\",\"unexpected\":true}","{\"kind\":\"agent\",\"ids\":[]}","{\"mode\":\"restricted\",\"clauses\":[{\"entity_ids\":[true]}]}"})
            Assert.Throws<AgentControlException>(()=>WorkstationAgentScope.Build(f,Access(c,new ReportDecision("workstations.usb",true,[Grant(scope,Fields)]))));
    }
}
