using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Diagnostics;
using Sli.Server.Jobs;
using Sli.Server.Workstations;
using Xunit;
namespace Sli.Server.Tests.Workstations;
public sealed class WorkstationJobTests
{
    [Fact]public void Projection_progress_changes_the_pinned_generation_without_changing_rights_or_inventory_partitions()
    {
        var handler=new JsonObject{["handler_id"]="workstations.overview-project"};
        var source=new JsonObject{["source_instance_id"]="workstations:projection",["revision"]="1",["projection_progress"]="first"};
        var first=WorkstationJobPlugin.Pin(handler,source,"same-slot");source["projection_progress"]="second";
        var next=WorkstationJobPlugin.Pin(handler,source,"same-slot");
        Assert.NotEqual(first.Pinned["generation"]!.ToString(),next.Pinned["generation"]!.ToString());
        Assert.Equal(first.Partition,next.Partition);Assert.Equal("workstations.overview-project",next.Partition);
        Assert.Equal(first.Pinned["policy_revision"]!.ToString(),next.Pinned["policy_revision"]!.ToString());
    }
    sealed class Unavailable(string state):Sli.Server.Infrastructure.IPostgresConnectionFactory
    {public Task<NpgsqlConnection> OpenAsync(CancellationToken ct)=>throw new PostgresException("private fixture driver message","ERROR","ERROR",state);}
    [Theory][InlineData("42P01","source_not_initialized")][InlineData("42501","source_access_denied")][InlineData("57014","source_timeout")][InlineData("08006","source_unavailable")]
    public async Task Family_source_failures_include_connection_open_and_preserve_safe_result_codes(string state,string reason)
    {
        var fields=WorkstationReportContract.Fields;
        var facts=new AccessFacts(false,"operator",[],[],fields.Select(f=>JsonSerializer.SerializeToElement(new{capability_key="field."+f,effect="allow",scope_json=new{kind="all"}})).ToArray(),[],[],
            [JsonSerializer.SerializeToElement(new{report_key="workstations.processes",effect="allow",field_categories=fields,allowed_actions=new[]{"view"},scope_json=new{kind="agent",ids=new[]{"fixture-agent"}}})],
            [JsonSerializer.SerializeToElement(new{report_key="workstations.processes",version=1,dataset_version=1,fields_json=fields.Select(f=>new{category=f}),actions_json=new[]{"view"},definition_json=new{field_categories=fields,actions=new[]{"view"}}})]);
        var access=new ReportEligibility().Compose(facts,new CapabilityComposer().Compose(facts));
        var reader=new WorkstationReports(new Unavailable(state),new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build());
        var result=await reader.ReadAsync(new("workstations.processes",new(){["period"]=new JsonObject{["from_utc"]="2026-11-01T00:00:00Z",["to_utc"]="2026-11-02T00:00:00Z"}},25,null,null),facts,access,TestContext.Current.CancellationToken);
        Assert.Equal("error",result["state"]!.GetValue<string>());Assert.Equal(reason,result["coverage"]!["reason"]!.GetValue<string>());Assert.DoesNotContain("private fixture",result.ToJsonString());
    }
    [Fact]public void Compiled_plugin_registers_both_reviewed_handlers_and_manifests()
    {
        var catalog=CoreJobPluginCatalog.Compiled();Assert.Contains("sli.workstations",catalog.Owners);var registry=catalog.Registry(null);
        var handlers=registry.Handlers.Where(h=>h["plugin_id"]!.GetValue<string>()=="sli.workstations").ToArray();Assert.Equal(2,handlers.Length);
        foreach(var h in handlers){Assert.Equal("light",h["resource_profile"]!.GetValue<string>());Assert.True(catalog.Contains(h));catalog.Resolve(h);}
        Assert.Contains(handlers,h=>h["handler_id"]!.GetValue<string>()=="workstations.evidence-retention");Assert.Contains(handlers,h=>h["handler_id"]!.GetValue<string>()=="workstations.overview-project");
    }
    [Fact]public void Inventory_schedule_keeps_domain_partition_policy_revision_and_manifest_fence()
    {
        var catalog=CoreJobPluginCatalog.Compiled();var registry=catalog.Registry(null);var source=new JsonObject{["plugin_id"]="sli.workstations",["source_instance_id"]="workstations:inventory:11",["revision"]="fixture-revision",["access_scope"]=new JsonObject{["kind"]="domain",["ids"]=new JsonArray(11)}};
        var spec=CoreJobScheduler.Create(registry,"light",source,DateTimeOffset.Parse("2026-10-19T12:00:00Z"),WorkstationJobPlugin.Pin).Single(j=>j["handler_id"]!.GetValue<string>()=="workstations.overview-project");
        Assert.Equal("workstations:inventory:11",spec["partition_key"]!.GetValue<string>());Assert.Equal("fixture-revision",spec["pinned_input"]!["policy_revision"]!.GetValue<string>());Assert.Equal(CoreJobJson.Digest(spec["pinned_input"]),spec["input_sha256"]!.GetValue<string>());registry.Resolve(spec);
    }
    [Theory][InlineData("0")][InlineData("3651")][InlineData("-1")][InlineData("1.0")][InlineData("１２")]
    public void Destructive_retention_policy_rejects_invalid_input(string value)=>Assert.Throws<WorkstationException>(()=>WorkstationJobPlugin.RetentionDays(value));
    [Theory][InlineData("1",1)][InlineData(" 90 ",90)][InlineData("3650",3650)]
    public void Retention_policy_preserves_source_bounds(string value,int expected)=>Assert.Equal(expected,WorkstationJobPlugin.RetentionDays(value));
    [Fact]public async Task Foreign_projection_source_is_rejected_before_database_access()
    {
        var catalog=CoreJobPluginCatalog.Compiled();var job=new JsonObject{["plugin_id"]="sli.workstations",["handler_id"]="workstations.overview-project",["source_instance_id"]="foreign-source"};await using var db=new NpgsqlConnection();
        Assert.Equal("workstation_projection_job_invalid",(await Assert.ThrowsAsync<WorkstationException>(()=>catalog.Resolve(job).Stage(db,job,TestContext.Current.CancellationToken))).Message);
    }
    [Fact]public void Overview_grant_does_not_borrow_legacy_fields_and_inventory_uses_its_resources()
    {
        var facts=new AccessFacts(false,"operator",[],[],[],[],[],[],[]);var caps=new CapabilityComposer().Compose(facts);
        AtomicReportGrant Grant(params string[] fields)=>new(JsonSerializer.SerializeToElement(new{kind="all"}),fields.ToHashSet(),new HashSet<string>{"view"},1,1);
        var legacy=new ReportDecision("workstations.logons",true,[Grant(WorkstationReportContract.Fields)]);
        var current=new ReportDecision("workstations.overview",true,[Grant("identity_basic","technical"),Grant("security","privilege")]);
        var access=new AccessDecision("operator",caps,[legacy,current]);
        Assert.Throws<AgentControlException>(()=>WorkstationAgentScope.Build(facts,access,true,"workstations.overview"));Assert.Throws<WorkstationException>(()=>WorkstationReportContract.Admit(access,"workstations.overview"));
        access=access with{Reports=[current with{Grants=[Grant(WorkstationReportContract.Fields)]}]};var predicate=WorkstationAgentScope.Build(facts,access,true,"workstations.overview");Assert.Contains("station_resources r where r.station_id=s.station_id",predicate.Sql);Assert.Contains("FALSE",predicate.Sql);
    }
    [Fact]public void Invalid_and_scoped_capability_denies_remain_independent_of_report_grants()
    {
        var deny=JsonSerializer.SerializeToElement(new{capability_key="workstations.read",effect="deny",scope_json=new{kind="domain",ids=new[]{11}}});
        var facts=new AccessFacts(false,"operator",[],[],[deny],[],[],[],[]);var caps=new CapabilityComposer().Compose(facts);
        var grant=new AtomicReportGrant(JsonSerializer.SerializeToElement(new{kind="all"}),WorkstationReportContract.Fields.ToHashSet(),new HashSet<string>{"view"},1,1);
        var access=new AccessDecision("operator",caps,[new("workstations.overview",true,[grant])]);var p=WorkstationAgentScope.Build(facts,access,true,"workstations.overview");Assert.Contains("NOT",p.Sql);Assert.Contains(p.Parameters,x=>x.Value is string[] a&&a.Contains("ad-domain:11"));
    }
}
