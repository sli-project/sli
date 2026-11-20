using System.Globalization;
using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Primitives;
using Sli.Server.Access;
using Sli.Server.Vpn;
using Xunit;

namespace Sli.Server.Tests.Vpn;

// Vectors from tests/reporting/test_nps_policy_denials_reporting.py.
public sealed class NpsPolicyDenialsReportingTests
{
    static readonly DateTimeOffset Start=DateTimeOffset.Parse("2026-10-01T00:00:00Z",CultureInfo.InvariantCulture);
    static readonly DateTimeOffset End=Start.AddDays(7);
    static CancellationToken Ct=>TestContext.Current.CancellationToken;
    static JsonObject Json(object value)=>VpnRouteTests.Json(value);
    static JsonObject Fact(int id,bool denied=true,string? policy="policy-a",string? reason="16",string? account="account-a",bool previous=false)=>Json(new
    {
        source_event_id=id,normalized_event_id=$"fact-{id}",occurred_at_utc=previous?Start.AddDays(-1):Start,
        semantic_type=denied?"remote_access.authentication.denied":"remote_access.authentication.allowed",
        facts_json=new {network_policy=policy,nas_identifier="nas-a",reason_code=reason,authentication_type="method-a",authentication_provider="provider-a"},
        roles_json=new {affected_entity=account},quality_json=new {identity_roles=new {affected_entity=new {state="resolved",provisional=false}}}
    });
    static JsonObject Compose(List<JsonObject> current,List<JsonObject>? previous=null,bool currentTruncated=false,bool previousTruncated=false,int minDecisions=0,int minGrowth=0)=>
        VpnPolicyDenials.Compose(current,previous??[],Start,End,currentTruncated,previousTruncated,minDecisions,minGrowth);
    static long Number(JsonNode? node)=>long.Parse(node!.ToString(),CultureInfo.InvariantCulture);
    static QueryCollection Query(params (string Key,string Value)[] values)=>new(values.ToDictionary(v=>v.Key,v=>new StringValues(v.Value)));
    static AccessFacts ScopedFacts(bool events=true,bool assigned=true)
    {
        var initial=VpnRouteTests.MakeFacts(false);
        var capability=JsonSerializer.SerializeToElement(new {capability_key="events.view",effect="allow",scope_json=new {kind="domain",ids=new[]{7}}});
        var grant=JsonSerializer.SerializeToElement(new {report_key="vpn.audit",effect="allow",scope_json=new {kind="domain",ids=new[]{7,8}},field_categories=Array.Empty<string>(),allowed_actions=new[]{"view"}});
        return initial with {DirectCapabilities=events?[..initial.DirectCapabilities,capability]:initial.DirectCapabilities,ReportAssignments=assigned?[grant]:[]};
    }
    sealed class Store : IVpnStore,IVpnReadSession
    {
        public readonly List<(string Sql,object?[] Values)> Calls=[];
        public bool EmitFact=true;
        public Task<IVpnReadSession> OpenAsync(CancellationToken ct)=>Task.FromResult<IVpnReadSession>(this);
        public ValueTask DisposeAsync()=>ValueTask.CompletedTask;
        public Task<List<JsonObject>> ReadAsync(string sql,object?[] values,CancellationToken ct)
        {
            Calls.Add((sql,values));
            if(sql.Contains("read_plugin_states_v1",StringComparison.Ordinal)) return Task.FromResult(new List<JsonObject>{Json(new {installed=true,enabled=true})});
            if(sql=="module_disabled:NpsPolicyDenials")
            {
                var rows=new List<JsonObject>();
                if(EmitFact && Calls.Count(c=>c.Sql=="module_disabled:NpsPolicyDenials")==1)
                {var row=Fact(1);row["occurred_at_utc"]=((DateTimeOffset)values[0]!).ToString("O",CultureInfo.InvariantCulture);rows.Add(row);}
                return Task.FromResult(rows);
            }
            // No registered Accounting sources; retained NPS facts still make a domain selectable.
            if(sql==VpnSql.SessionDomains) return Task.FromResult(new List<JsonObject>());
            if(sql=="select id,fqdn from domains order by id limit 10001")
                return Task.FromResult(new List<JsonObject>{Json(new {id=7,fqdn="a.example.test"}),Json(new {id=8,fqdn="b.example.test"})});
            throw new InvalidOperationException("Unexpected read: "+sql);
        }
    }

    [Fact] public void Decisions_share_missing_dimensions_and_unknown_identities_remain_separate()
    {
        var payload=Compose([Fact(1),Fact(2,denied:false),Fact(3,account:null),Fact(4,policy:null,reason:null)]);
        var metrics=payload["metrics"]!;
        foreach(var (key,want) in new[]{("allowed",1),("denied",3),("denial_share",75),("affected_accounts",1),("unknown_identity_denials",1),("missing_policy",1),("missing_reason",1)})
            Assert.Equal(want,Number(metrics[key]));
        Assert.Equal(2,payload["items"]!.AsArray().Count);
        Assert.Equal(new long[]{6273,6272,6273,6273},payload["events"]!.AsArray().Select(r=>Number(r!["event_id"])));
        Assert.Equal("not_proven",payload["coverage"]!["current"]!["source_completeness"]!.ToString());
    }
    [Fact] public void Growth_compares_equal_windows_and_totals_across_reasons()
    {
        var payload=Compose([Fact(1),Fact(2),Fact(3,reason:"36")],[Fact(4,previous:true)]);
        var row=payload["items"]!.AsArray().Single(r=>r!["reason_code"]!.ToString()=="16")!;
        Assert.Equal(1,Number(row["previous_denied"]));Assert.Equal(1,Number(row["growth"]));
        Assert.Equal(row["first_denial_utc"]!.ToString(),row["last_denial_utc"]!.ToString());
        Assert.Equal(1,Number(payload["metrics"]!["growing_policies"]));Assert.Equal(1,Number(payload["metrics"]!["growing_nas"]));
        Assert.Equal("2026-09-24T00:00:00Z",payload["coverage"]!["previous"]!["from_utc"]!.ToString());
    }
    [Fact] public void Minimums_filter_groups_without_redefining_slice_metrics()
    {
        var payload=Compose([Fact(1),Fact(2,denied:false),Fact(3,policy:"policy-b")],minDecisions:2,minGrowth:1);
        var row=Assert.Single(payload["items"]!.AsArray())!;
        Assert.Equal(2,Number(row["decisions"]));Assert.Equal(50,Number(row["denial_share"]));Assert.Equal(2,Number(payload["metrics"]!["denied"]));
    }
    [Theory] [InlineData(true,false)] [InlineData(false,true)]
    public void Either_truncated_window_suppresses_growth_and_growth_filtered_groups(bool current,bool previous)
    {
        var payload=Compose([Fact(1)],currentTruncated:current,previousTruncated:previous);
        Assert.Null(payload["items"]![0]!["growth"]);Assert.Null(payload["metrics"]!["growing_policies"]);Assert.Null(payload["metrics"]!["growing_nas"]);
        Assert.Equal("truncated",payload["coverage"]![current?"current":"previous"]!["state"]!.ToString());
        Assert.Empty(Compose([Fact(1)],currentTruncated:current,previousTruncated:previous,minGrowth:1)["items"]!.AsArray());
    }
    [Fact] public void Provisional_accounts_are_unknown_in_groups_metrics_and_evidence()
    {
        var row=Fact(1);row["quality_json"]!["identity_roles"]!["affected_entity"]!["provisional"]=true;
        var payload=Compose([row]);Assert.Equal(0,Number(payload["metrics"]!["affected_accounts"]));
        Assert.Equal(1,Number(payload["items"]![0]!["unknown_identity_denials"]));Assert.Equal("unknown",payload["events"]![0]!["identity_state"]!.ToString());
    }
    [Fact] public void Previous_only_and_reasonless_groups_remain_distinct()
    {
        var payload=Compose([Fact(1,reason:null),Fact(2)],[Fact(3,policy:"old-policy",previous:true)]);
        var rows=payload["items"]!.AsArray();Assert.Equal(2,rows.Count);
        Assert.Contains(rows,r=>r!["reason_code"] is null);Assert.Contains(rows,r=>r!["reason_code"]?.ToString()=="16");
        Assert.Equal(1,Number(payload["metrics"]!["growing_policies"]));
    }
    [Fact] public void Authentication_provider_is_part_of_the_slice()
    {
        var other=Fact(2);other["facts_json"]!["authentication_provider"]="provider-b";
        Assert.Equal(2,Compose([Fact(1),other])["items"]!.AsArray().Count);
    }
    [Theory] [InlineData(0)] [InlineData(32)]
    public void Composer_rejects_empty_or_unbounded_windows(int days)
    {
        Assert.Equal("nps_policy_window_or_threshold_invalid",Assert.Throws<VpnInputException>(()=>VpnPolicyDenials.Compose([],[],Start,Start.AddDays(days))).Message);
    }
    [Fact] public async Task Domain_options_without_report_grant_do_not_read_storage()
    {
        var store=new Store();Assert.Empty(await VpnReports.DomainOptions(store,new VpnAccess(ScopedFacts(assigned:false)),Ct));Assert.Empty(store.Calls);
    }
    [Fact] public async Task Domain_options_keep_authorized_Nps_domains_without_accounting()
    {
        var store=new Store();var options=await VpnReports.DomainOptions(store,new VpnAccess(ScopedFacts()),Ct);
        Assert.True(JsonNode.DeepEquals(JsonSerializer.SerializeToNode(new[]{new {value="7",label="a.example.test"}}),JsonSerializer.SerializeToNode(options)));
    }
    [Theory] [InlineData(7,true,true,true)] [InlineData(8,true,true,false)] [InlineData(7,false,true,false)] [InlineData(7,true,false,false)]
    public async Task Domain_grant_and_event_access_are_both_required_before_facts(long domain,bool events,bool assigned,bool allowed)
    {
        var store=new Store();var payload=await VpnPolicyDenials.Read(store,new VpnAccess(ScopedFacts(events,assigned)),new(domain,"view","UTC",Start,End,100,0,""),Query(),Ct);
        Assert.Equal(allowed?"partial":"denied",payload["state"]!.ToString());Assert.Equal(allowed?2:0,store.Calls.Count);
    }
    [Fact] public async Task Reader_uses_retained_domain_latest_version_bound_filters_and_equal_windows()
    {
        var store=new Store();var payload=await VpnPolicyDenials.Read(store,new VpnAccess(ScopedFacts()),new(7,"view","UTC",Start,End,100,0,""),Query(("policy","policy-a"),("method","method-a")),Ct);
        Assert.Equal(1,Number(payload["collections"]!["policy_denials"]![0]!["denied"]));Assert.Equal(2,store.Calls.Count);
        foreach(var (sql,values) in store.Calls)
        {
            Assert.Contains("policy-a",values);Assert.Contains("method-a",values);Assert.DoesNotContain("policy-a",sql);
            Assert.Equal("7",values[2]);
        }
        Assert.Equal(Start,store.Calls[0].Values[0]);Assert.Equal(End,store.Calls[0].Values[1]);
        Assert.Equal(Start.AddDays(-7),store.Calls[1].Values[0]);Assert.Equal(Start,store.Calls[1].Values[1]);
    }
    public static TheoryData<string,int,string,string,bool> HistoricalWindows=>new()
    {
        {"policy_denials",7,"2026-10-01T00:00:00Z","2026-09-24T00:00:00Z",false},
        {"policy_denials",31,"2026-10-01T00:00:00Z","2026-08-31T00:00:00Z",false},
        {"policy_denials",32,"2026-10-02T00:00:00Z","2026-09-01T00:00:00Z",true},
        {"policy_denials",90,"2026-11-29T00:00:00Z","2026-10-29T00:00:00Z",true},
        {"policy_denials_growth",7,"2026-10-01T00:00:00Z","2026-09-24T00:00:00Z",false},
        {"policy_denials_growth",31,"2026-10-01T00:00:00Z","2026-08-31T00:00:00Z",false},
        {"policy_denials_growth",32,"2026-10-02T00:00:00Z","2026-09-01T00:00:00Z",true},
        {"policy_denials_growth",90,"2026-11-29T00:00:00Z","2026-10-29T00:00:00Z",true},
        {"policy_denials_events",7,"2026-10-01T00:00:00Z","2026-09-24T00:00:00Z",false},
        {"policy_denials_events",31,"2026-10-01T00:00:00Z","2026-08-31T00:00:00Z",false},
        {"policy_denials_events",32,"2026-10-02T00:00:00Z","2026-09-01T00:00:00Z",true},
        {"policy_denials_events",90,"2026-11-29T00:00:00Z","2026-10-29T00:00:00Z",true}
    };



}
