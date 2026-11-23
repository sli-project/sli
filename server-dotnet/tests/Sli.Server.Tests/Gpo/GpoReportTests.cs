using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Sli.Server.Gpo;
using Xunit;
using static Sli.Server.Gpo.GpoJson;

namespace Sli.Server.Tests.Gpo;

public sealed class GpoReportTests
{
    internal static JsonObject Vectors([System.Runtime.CompilerServices.CallerFilePath] string file="") => JsonNode.Parse(File.ReadAllText(Path.Combine(Path.GetDirectoryName(file)!,"source-vectors.json")))!.AsObject();
    internal sealed class Store : IGpoReadStore, IGpoSnapshotReadStore
    {
        public JsonObject Pair=Vectors()["pair"]!.AsObject();public int Reads;public long[]? Domains;public Exception? Error;
        public JsonObject? PolicyHistory;
        public readonly List<(long Domain, string PolicyId, GpoPolicySnapshot Snapshot)> Snapshots = [];
        public Task<JsonObject> PairAsync(long[]? domains,CancellationToken ct) { Reads++;Domains=domains;if(Error is {} e) throw e;return Task.FromResult(Pair.Copy()); }
        public Task<JsonObject> GraphAsync(JsonObject s,long[]? domains,CancellationToken ct) { Reads++;Domains=domains;return Task.FromResult(Vectors()["effective"]![0]!["graph"]!.AsObject().Copy()); }
        public Task<JsonObject> HistoryAsync(long[]? domains,DateTimeOffset from,DateTimeOffset to,string q,CancellationToken ct) { Reads++;Domains=domains;return Task.FromResult(new JsonObject { ["state"]="unavailable",["items"]=new JsonArray(),["coverage"]=new JsonObject { ["state"]="unavailable" } }); }
        public Task<JsonObject> PolicyHistoryAsync(long[] domains,DateTimeOffset from,DateTimeOffset to,string policyId,string guid,CancellationToken ct)
        {
            Reads++;Domains=domains;
            return Task.FromResult(PolicyHistory?.Copy()??new JsonObject { ["state"]="unavailable",["items"]=new JsonArray() });
        }
        public Task<IReadOnlyList<GpoPolicySnapshot>> PolicySnapshotsAsync(long domain, string policyId,
            (Guid Before, Guid After)? comparison, CancellationToken ct)
        {
            Reads++;
            Domains = [domain];
            IReadOnlyList<GpoPolicySnapshot> rows = Snapshots.Where(entry => entry.Domain == domain && entry.PolicyId == policyId)
                .Select(entry => entry.Snapshot).Where(snapshot => comparison is not { } pair || snapshot.Id == pair.Before || snapshot.Id == pair.After)
                .OrderByDescending(snapshot => snapshot.ObservedAt).ToArray();
            return Task.FromResult(rows);
        }
    }
    static GpoRequest Request(string view="all",string? tab=null)=>new(view,"",tab,null,"asc",500,null,"UTC",Stamp("2026-10-01T00:00:00Z"),Stamp("2026-10-08T00:00:00Z"));
    // Minimal observed snapshot from tests/reports/test_gpo_review_categories.py.
    internal static JsonObject ReviewSnapshot()=>JsonNode.Parse("""
        {"observed_at":"2026-10-07T00:00:00Z","completed_at":"2026-10-07T00:05:00Z",
         "collection_status":"complete","source_states":{"links":{"status":"observed"}},
         "gpos":[{"id":"synthetic-policy","display_name":"Synthetic policy","link_ids":[],
                  "source_states":{"report":{"status":"observed"},"sysvol_gpt":{"status":"observed"},"links":{"status":"observed"}},
                  "computer":{"enabled":true,"settings_count":0,"directory_version":1,"sysvol_version":1}}]}
        """)!.AsObject();
    [Fact] public async Task Agent_gpt_observation_and_owner_reach_the_policy_columns()
    {
        var snapshot=ReviewSnapshot();var policy=Assert.Single(snapshot.Rows("gpos"));
        policy["source_states"]!.AsObject().Remove("sysvol_gpt");
        policy["source_states"]!["gpt"]=new JsonObject { ["status"]="observed" };
        policy["computer"]!["sysvol_version"]=2;
        policy["owner"]=new JsonObject { ["name"]="EXAMPLE\\synthetic-owner",["sid"]="S-1-5-21-100000001-200000002-300000003-512" };
        var store=new Store { Pair=new JsonObject { ["state"]="available",["current"]=snapshot } };
        var payload=await GpoReport.QueryAsync(store,[1],Request(),TestContext.Current.CancellationToken);
        var row=Assert.Single(payload.Rows("items"));
        Assert.Equal("EXAMPLE\\synthetic-owner",row.Text("owner"));
        Assert.NotEmpty(row.Text("reason_titles"));
        Assert.Contains(row.Rows("reasons"),r=>r.Text("code")=="version_mismatch"&&r.Text("category")=="deviation");
    }
    [Fact] public void Empty_unlinked_policy_is_only_an_assignment_question_and_does_not_mutate_snapshot()
    {
        var snapshot=ReviewSnapshot();var original=snapshot.DeepClone();
        Assert.Empty(GpoInventory.Filter(snapshot,"attention").Items);
        Assert.Empty(GpoInventory.Filter(snapshot,"unverified").Items);
        var policy=Assert.Single(GpoInventory.Filter(snapshot,"assignment").Items.OfType<JsonObject>());
        var reasons=policy.Rows("reasons").ToArray();
        Assert.Equal(new[]{"unlinked","empty_enabled_side"},reasons.Select(r=>r.Text("code")));
        Assert.All(reasons,r=>
        {
            Assert.Equal("assignment",r.Text("category"));Assert.Equal("low",r.Text("priority"));Assert.NotEmpty(r.Text("next"));
        });
        Assert.True(JsonNode.DeepEquals(original,snapshot));
    }
    [Fact] public void Missing_setting_count_does_not_prove_that_an_enabled_policy_is_empty()
    {
        var snapshot=ReviewSnapshot();var policy=Assert.Single(snapshot.Rows("gpos"));policy["computer"]!.AsObject().Remove("settings_count");
        Assert.DoesNotContain(GpoInventory.Reasons(policy,snapshot).OfType<JsonObject>(),r=>r.Text("code")=="empty_enabled_side");
    }
    [Fact] public void Partial_report_is_unverified_information_and_not_a_confirmed_deviation()
    {
        var snapshot=ReviewSnapshot();snapshot["gpos"]![0]!["source_states"]!["report"]!["status"]="partial";
        var policy=Assert.Single(GpoInventory.Filter(snapshot,"unverified").Items.OfType<JsonObject>());
        var reason=policy.Rows("reasons").First();Assert.Equal("source_unverified",reason.Text("code"));Assert.Equal("unverified",reason.Text("category"));
        Assert.Empty(GpoInventory.Filter(snapshot,"attention").Items);
    }
    [Theory]
    [InlineData("observed","attention","deviation","high")]
    [InlineData("failed","unverified","unverified","medium")]
    [InlineData("partial","unverified","unverified","medium")]
    public void Version_deviation_requires_verified_sources(string status,string view,string category,string priority)
    {
        var snapshot=ReviewSnapshot();var policy=Assert.Single(snapshot.Rows("gpos"));
        policy["computer"]!["sysvol_version"]=2;policy["source_states"]!["sysvol_gpt"]!["status"]=status;
        var row=Assert.Single(GpoInventory.Filter(snapshot,view).Items.OfType<JsonObject>());
        Assert.Equal(category,Assert.Single(row.Rows("reasons"),r=>r.Text("code")=="version_mismatch").Text("category"));
        Assert.Equal(priority,row.Rows("reasons").First().Text("priority"));
        if(status!="observed") Assert.Empty(GpoInventory.Filter(snapshot,"attention").Items);
    }
    [Fact] public async Task Snapshot_contract_separates_review_categories_in_metrics_and_row_details()
    {
        var snapshot=ReviewSnapshot();snapshot["gpos"]![0]!["source_states"]!["sysvol_gpt"]!["status"]="failed";
        var store=new Store { Pair=new JsonObject { ["state"]="available",["current"]=snapshot } };
        var payload=await GpoReport.QueryAsync(store,[1],Request(tab:"gpos"),TestContext.Current.CancellationToken);
        Assert.Empty(payload["window"]!.AsObject());Assert.Equal("2026-10-07T00:00:00Z",payload["coverage"].Text("observed_at_utc"));
        var expected=new Dictionary<string,long> { ["attention"]=0,["unverified"]=1,["assignment"]=1,["all"]=1,["linked"]=0,["unlinked"]=1 };
        var metrics=payload.Rows("metrics").ToArray();Assert.Equal(expected.Count,metrics.Length);
        foreach(var metric in metrics) Assert.Equal(expected[metric.Text("key")],metric.Number("value"));
        var row=Assert.Single(payload.Rows("items"));Assert.Null(row["reason_titles"]);Assert.Equal(0,row.Number("reason_count"));
        Assert.Equal("medium",row.Text("priority"));Assert.NotEmpty(row.Text("next_step"));
        Assert.NotEmpty(row.Text("unverified_titles"));Assert.NotEmpty(row.Text("assignment_titles"));
        string fact=row.Rows("reasons").First().Text("fact");Assert.DoesNotContain("sysvol_gpt",fact);Assert.Contains("SYSVOL / GPT.INI",fact);
    }
    [Fact] public async Task Inventory_filters_deviations_and_preserves_policy_values()
    {
        var snapshot=ReviewSnapshot();
        var changed=snapshot["gpos"]![0]!.DeepClone().AsObject();
        changed["id"]="synthetic-changed-policy";changed["display_name"]="Changed policy";
        changed["computer"]!["sysvol_version"]=2;
        changed["link_ids"]=new JsonArray("synthetic-link");
        changed["owner"]=new JsonObject { ["name"]="synthetic-owner" };
        changed["modification_time"]="2026-10-07T00:00:00Z";
        snapshot["gpos"]!.AsArray().Add(changed);
        var store=new Store { Pair=new JsonObject { ["state"]="available",["current"]=snapshot } };
        foreach(var (view,ids) in new (string,string[])[] {
            ("all",["synthetic-changed-policy","synthetic-policy"]),
            ("attention",["synthetic-changed-policy"]),("linked",["synthetic-changed-policy"]),("unlinked",["synthetic-policy"]) })
        {
            var result=await GpoReport.QueryAsync(store,[1],Request(view),TestContext.Current.CancellationToken);
            Assert.Equal(ids,result.Rows("items").Select(r=>r.Text("id")));
            Assert.Equal(ids.Length,result.Number("filtered_count"));
            var row=result.Rows("items").SingleOrDefault(r=>r.Text("id")=="synthetic-changed-policy");
            if(row is not null) {
                Assert.Equal("synthetic-owner",row.Text("owner"));Assert.NotEmpty(row.Text("reason_titles"));
                Assert.Equal("2026-10-07T00:00:00Z",row.Text("modification_time"));Assert.Equal(1,row.Number("link_count"));
            }
        }
    }
    [Fact] public void Effective_access_matches_source_for_ordered_ACEs_membership_unknowns_queries_and_budgets()
    {
        foreach(var v in Vectors().Rows("effective"))
        {
            int rows=(int)(v["options"]?["max_rows"]?.GetValue<int>()??2000),depth=v["options"]?["max_depth"]?.GetValue<int>()??16;
            var result=GpoEffectiveAccess.Analyze(v["snapshot"]!.AsObject(),v["graph"]!.AsObject(),v.Text("mode"),v.Text("q"),rows,depth);
            Assert.True(JsonNode.DeepEquals(result,v["result"]),$"{v.Text("name")}/{v.Text("mode")}/{v.Text("q")}: {result}");
        }
    }
    [Fact] public void Link_inheritance_matches_source_including_missing_chain_and_site_boundaries()
    {
        foreach(var v in Vectors().Rows("links")) Assert.True(JsonNode.DeepEquals(v["result"],GpoEffectiveAccess.LinkedScopes(v["snapshot"]!.AsObject())),v.Text("name"));
    }
    [Fact] public async Task Missing_source_and_unknown_links_remain_explicit()
    {
        var store=new Store { Pair=new JsonObject { ["state"]="not_collected",["current"]=null,["previous"]=null } };
        var result=await GpoReport.QueryAsync(store,[1],Request(),TestContext.Current.CancellationToken);Assert.Equal("not_collected",result.Text("state"));Assert.Empty(result.Rows("items"));
        store.Pair=Vectors()["pair"]!.AsObject().Copy();store.Pair["current"]!["source_states"]!["links"]!["status"]="failed";
        result=await GpoReport.QueryAsync(store,[1],Request("unlinked"),TestContext.Current.CancellationToken);Assert.Equal("partial",result.Text("state"));Assert.Empty(result.Rows("items"));Assert.Contains(result.Rows("limitations"),l=>l.Text("code")=="links_not_observed");
    }
    [Fact] public void Stored_snapshot_validation_rejects_corruption_and_hash_mismatch()
    {
        var s=Vectors()["pair"]!["current"]!.AsObject();string json=s.ToJsonString();var hash=Convert.FromHexString(Hash(s));Assert.NotNull(GpoReadStore.ValidateSnapshot(json,hash));
        Assert.Throws<GpoSourceException>(()=>GpoReadStore.ValidateSnapshot(json,new byte[32]));s["schema_version"]="untrusted";Assert.Throws<GpoSourceException>(()=>GpoReadStore.ValidateSnapshot(s.ToJsonString(),null));
    }
    [Theory]
    [InlineData("view","unknown","report_parameter_invalid:view")]
    [InlineData("limit","0","report_limit_invalid")]
    [InlineData("limit","10001","report_limit_invalid")]
    [InlineData("tab","unknown","report_tab_invalid")]
    [InlineData("sort","owner","report_sort_invalid")]
    [InlineData("tz","Missing/Zone","report_timezone_invalid")]
    [InlineData("injected","x","report_parameter_unknown:injected")]
    [InlineData("period","bad","report_period_invalid")]
    public void Invalid_query_contract(string key,string value,string code)
    {
        var q=new QueryCollection(new Dictionary<string,Microsoft.Extensions.Primitives.StringValues>{{key,value}});Assert.Equal(code,Assert.Throws<ArgumentException>(()=>GpoRequest.Parse(q,DateTimeOffset.UtcNow)).Message);
    }
    [Fact] public void Period_dates_are_local_and_exact_instant_end_is_exclusive()
    {
        var c=new DefaultHttpContext();c.Request.QueryString=new("?period=custom&from=2026-10-01&to=2026-10-01&tz=Asia/Bangkok");var r=GpoRequest.Parse(c.Request.Query,DateTimeOffset.UtcNow);
        Assert.Equal(Stamp("2026-09-30T17:00:00Z"),r.From);Assert.Equal(TimeSpan.FromDays(1),r.To-r.From);
        c.Request.QueryString=new("?period=custom&from=2026-10-01T00:00:00Z&to=2026-10-01T01:00:00Z");r=GpoRequest.Parse(c.Request.Query,DateTimeOffset.UtcNow);Assert.Equal(TimeSpan.FromHours(1),r.To-r.From);
        c.Request.QueryString=new("?period=custom&from=2026-10-01T00:00:00&to=2026-10-01T01:00:00");Assert.Equal("report_period_invalid",Assert.Throws<ArgumentException>(()=>GpoRequest.Parse(c.Request.Query,DateTimeOffset.UtcNow)).Message);
    }
    [Fact] public void Csv_uses_view_columns_labels_quotes_and_formula_defense()
    {
        var columns=JsonNode.Parse("""[{"label":"Name","path":"name"},{"label":"Enabled","path":"enabled"}]""")!.AsArray();
        string csv=GpoEndpoints.Csv(columns,[new JsonObject { ["name"]=" =formula,\"x\"",["enabled"]=true }]);
        Assert.Equal("Name,Enabled\r\n\"' =formula,\"\"x\"\"\",True\r\n",csv);
    }
    [Fact] public async Task History_unavailability_is_error_and_keeps_period_not_false_empty()
    {
        var result=await GpoReport.QueryAsync(new Store(),[1],Request(tab:"changes"),TestContext.Current.CancellationToken);Assert.Equal("error",result.Text("state"));Assert.Empty(result["collections"].Rows("changes"));Assert.Contains(result.Rows("limitations"),l=>l.Text("code")=="history_unavailable");Assert.Equal("2026-10-01T00:00:00Z",result["window"].Text("from_utc"));Assert.Equal("2026-10-08T00:00:00Z",result["window"].Text("to_utc_exclusive"));
    }
    [Fact] public void Search_and_limit_preserve_Python_unicode_behavior()
    {
        Assert.True(Contains(new JsonObject { ["name"]="Straße" },"STRASSE"));
        var context=new DefaultHttpContext();context.Request.QueryString=new("?limit=1_000");Assert.Equal(1000,GpoRequest.Parse(context.Request.Query,DateTimeOffset.UtcNow).Limit);
        context.Request.QueryString=new("?limit=%D9%A1%D9%A0");Assert.Equal(10,GpoRequest.Parse(context.Request.Query,DateTimeOffset.UtcNow).Limit);
    }}
