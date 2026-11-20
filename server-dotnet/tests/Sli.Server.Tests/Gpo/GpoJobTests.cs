using System.Text.Json.Nodes;
using Sli.Server.Gpo;
using CoreJobJson = Sli.Server.Jobs.CoreJobJson;
using CoreJobPluginCatalog = Sli.Server.Jobs.CoreJobPluginCatalog;
using CoreJobScheduler = Sli.Server.Jobs.CoreJobScheduler;
using CoreJobContractException = Sli.Server.Jobs.CoreJobContractException;
using Sli.Server.Tests.Jobs;
using Xunit;
using static Sli.Server.Gpo.GpoJson;

namespace Sli.Server.Tests.Gpo;

public sealed class GpoJobTests
{
    const string Id="00000000-0000-4000-8000-000000000501";
    sealed class Store : IGpoJobStore
    {
        internal bool Enabled=true,Fenced,Persisted;internal JsonObject Payload=new() { ["gpos"]=new JsonArray(new JsonObject { ["display_name"]="Синтетическая политика" }) };
        internal JsonObject Manifest=new() { ["manifest_id"]=Id,["manifest_sha256"]=new string('a',64),["domain_id"]=1,["coverage_state"]="complete",["members"]=new JsonArray(new JsonObject { ["family"]="gpo_v2",["source_id"]="00000000-0000-4000-8000-000000000504",["payload_sha256"]=new string('b',64) }) };
        public Task<bool> EnabledAsync(CancellationToken ct)=>Task.FromResult(Enabled);
        public Task<JsonObject> ManifestAsync(string id,CancellationToken ct) { Assert.Equal(Id,id);return Task.FromResult(Manifest.Copy()); }
        public Task<JsonObject> SourceAsync(string id,string hash,CancellationToken ct) { Assert.Equal(new string('b',64),hash);return Task.FromResult(Payload.Copy()); }
        public Task FenceAsync(JsonObject job,CancellationToken ct) { Fenced=true;return Task.CompletedTask; }
        public Task PersistAsync(JsonObject job,JsonObject projection,JsonObject payload,CancellationToken ct) { Assert.True(Fenced);Assert.Equal(Hash(payload),projection.Text("output_sha256"));Persisted=true;return Task.CompletedTask; }
    }
    static JsonObject Job(string handler="gpo-snapshot")
    {
        var j=CoreJobTests.Job(handler);j["source_instance_id"]="ad-domain:1";j["pinned_input"]=new JsonObject { ["manifest_id"]=Id,["snapshot_sha256"]=new string('a',64),["domain_id"]=1,["generation"]=Id,["input_range"]=new JsonArray(Id),["policy_revision"]="1",["continuation"]=null };j["input_sha256"]=CoreJobJson.Digest(j["pinned_input"]);return j;
    }
    [Fact] public void Both_long_handlers_are_discovered_through_compiled_plugin_interface()
    {
        var catalog=CoreJobPluginCatalog.Compiled();Assert.Contains("sli.gpo",catalog.Owners);foreach(string h in new[]{"gpo-snapshot","gpo-acquisition"}) Assert.NotNull(catalog.Resolve(Job(h)));Assert.Equal(2,catalog.Registry(null).Identities("long").Count);
    }
    [Fact] public void Scheduler_pins_exact_manifest_hash_domain_revision_and_deduplicated_partition()
    {
        var source=new JsonObject { ["plugin_id"]="sli.gpo",["source_instance_id"]="ad-domain:1",["domain_id"]=1,["manifest_id"]=Id,["snapshot_sha256"]=new string('a',64),["revision"]="1",["access_scope"]=new JsonObject { ["kind"]="domain",["ids"]=new JsonArray(1) } };
        var specs=CoreJobScheduler.Create(CoreJobTests.Registry(),"long",source,Stamp("2026-10-01T00:01:00Z"),GpoJobPlugin.Pin).ToArray();Assert.Single(specs);var j=specs[0];Assert.Equal("gpo-snapshot",j.Text("handler_id"));Assert.Equal("ad-snapshot",j.Text("partition_key"));Assert.Equal(Id,j["pinned_input"].Text("manifest_id"));Assert.Equal(source["access_scope"]!.ToJsonString(),j["access_scope"]!.ToJsonString());CoreJobTests.Registry().Resolve(j);
        Assert.Empty(CoreJobScheduler.Create(CoreJobTests.Registry(),"light",source,DateTimeOffset.UtcNow,GpoJobPlugin.Pin));
    }
    [Fact] public async Task Stage_is_pure_and_publication_rechecks_exact_computation_before_writing()
    {
        var store=new Store();var job=Job();var r=await GpoJobPlugin.StageAsync(store,job,TestContext.Current.CancellationToken);Assert.Equal("success",r.Text("status"));Assert.False(store.Fenced);Assert.False(store.Persisted);Assert.Equal(Id+":ad.gpo.v2:v1",r["projection_results"]!["ad.gpo.v2"].Text("output_identity"));
        await GpoJobPlugin.PublishAsync(store,job,r,TestContext.Current.CancellationToken);Assert.True(store.Persisted);
        store.Persisted=false;store.Payload["gpos"]![0]!["display_name"]="changed";
        Assert.Equal("snapshot_result_changed",(await Assert.ThrowsAsync<CoreJobContractException>(()=>GpoJobPlugin.PublishAsync(store,job,r,TestContext.Current.CancellationToken))).Message);Assert.False(store.Persisted);
    }
    [Theory] [InlineData("gpo-snapshot")] [InlineData("gpo-acquisition")]
    public async Task Acquisition_is_blocked_without_external_collection_and_disabled_plugin_never_writes(string handler)
    {
        var store=new Store { Enabled=false };var j=Job(handler);var r=await GpoJobPlugin.StageAsync(store,j,TestContext.Current.CancellationToken);Assert.Equal("blocked",r.Text("status"));Assert.Equal(handler=="gpo-snapshot"?"snapshot_plugin_disabled":OperatingSystem.IsWindows()?"acquisition_requires_agent":"acquisition_disabled_on_linux",r.Text("error_code"));
        await GpoJobPlugin.PublishAsync(store,j,r,TestContext.Current.CancellationToken);Assert.False(store.Persisted);Assert.False(store.Fenced);
    }
    [Theory] [InlineData("domain_id")] [InlineData("manifest_sha256")] [InlineData("manifest_id")]
    public async Task Changed_source_identity_fails_without_writes(string field)
    {
        var store=new Store();store.Manifest[field]=field=="domain_id"?JsonValue.Create(2):JsonValue.Create("changed");Assert.Equal("snapshot_input_changed",(await Assert.ThrowsAsync<CoreJobContractException>(()=>GpoJobPlugin.StageAsync(store,Job(),TestContext.Current.CancellationToken))).Message);Assert.False(store.Persisted);
    }
    [Fact] public async Task Missing_gpo_part_and_record_budget_keep_contract_fail_closed()
    {
        var store=new Store();store.Manifest["members"]=new JsonArray(new JsonObject { ["family"]="ad_context_base" });var r=await GpoJobPlugin.StageAsync(store,Job(),TestContext.Current.CancellationToken);Assert.Equal("snapshot_part_not_collected",r.Text("error_code"));
        store=new Store();var j=Job();j["budget"]!["max_records"]=0;Assert.Equal("snapshot_record_budget_exceeded",(await Assert.ThrowsAsync<CoreJobContractException>(()=>GpoJobPlugin.StageAsync(store,j,TestContext.Current.CancellationToken))).Message);
    }
    [Fact] public async Task Partial_coverage_and_evidence_are_preserved()
    {
        var store=new Store();store.Manifest["coverage_state"]="partial";var r=await GpoJobPlugin.StageAsync(store,Job(),TestContext.Current.CancellationToken);Assert.Equal("partial",r.Text("status"));Assert.Equal("partial",r.Text("coverage_state"));Assert.Equal("ad-snapshot:"+Id,r["evidence_refs"]![0]!.ToString());
    }
    [Fact] public void Fields_and_domains_from_separate_grants_cannot_be_multiplied()
    {
        var fields=new HashSet<string>{"identity_basic","technical","security","privilege"};var rule=new Sli.Server.Access.ReportRule("ad.gpo.v2","ad.gpo.v2","domain",fields,new HashSet<string>(),null,false);
        var caps=new Sli.Server.Access.CapabilityComposer().Compose(new(false,"viewer",[],[],[],[],[],[],[]));
        var a=new Sli.Server.Access.AtomicReportGrant(System.Text.Json.JsonSerializer.SerializeToElement(new {kind="domain",ids=new[]{1}}),new HashSet<string>{"identity_basic","technical"},new HashSet<string>{"view"},1,1);
        var b=a with {FieldCategories=new HashSet<string>{"security","privilege"}};
        var access=new Sli.Server.Access.AccessDecision("viewer",caps,[new("ad.gpo.v2",true,[a,b])]);Assert.Equal("report_field_categories_not_allowed",Assert.Throws<UnauthorizedAccessException>(()=>GpoEndpoints.Authorize(access,"view",rule)).Message);
    }
    [Fact] public void Export_uses_only_scopes_of_atomic_export_grants()
    {
        var fields=new HashSet<string>{"identity_basic","technical","security","privilege"};var rule=new Sli.Server.Access.ReportRule("ad.gpo.v2","ad.gpo.v2","domain",fields,new HashSet<string>(),null,false);
        var caps=new Sli.Server.Access.CapabilityComposer().Compose(new(false,"viewer",[],[],[],[],[],[],[]));
        var view=new Sli.Server.Access.AtomicReportGrant(System.Text.Json.JsonSerializer.SerializeToElement(new {kind="domain",ids=new[]{1}}),fields,new HashSet<string>{"view"},1,1);
        var export=view with {Scope=System.Text.Json.JsonSerializer.SerializeToElement(new {kind="domain",ids=new[]{2}}),AllowedActions=new HashSet<string>{"view","export"}};
        var access=new Sli.Server.Access.AccessDecision("viewer",caps,[new("ad.gpo.v2",true,[view,export])]);Assert.Equal(new long[]{1,2},GpoEndpoints.Authorize(access,"view",rule));Assert.Equal(new long[]{2},GpoEndpoints.Authorize(access,"export",rule));
    }}
