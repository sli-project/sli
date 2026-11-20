using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Agents;
using Sli.Server.Vpn;
using Xunit;

namespace Sli.Server.Tests.Vpn;

// Behavioral vectors from tests/reports/test_g11a6_stage7_vpn_read_models.py.
public sealed class VpnReadModelTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static JsonObject Json(object value) => VpnRouteTests.Json(value);
    static string Sid(int id) => $"S-1-5-21-100000001-200000002-300000003-{id}";
    static VpnQuery Query => new(7,"view","UTC",DateTimeOffset.Parse("2026-08-21T10:00:00Z"),DateTimeOffset.Parse("2026-08-21T11:00:00Z"),200,0,"");
    const string Bounds = "domain_id=7&time_from=2026-08-21T10:00:00Z&time_to=2026-08-21T11:00:00Z&timezone=UTC";
    static string Route(string operation) => "/api/v1/reports/vpn.audit/" + operation;
    static Dictionary<long,JsonObject> Identities => new() { [101]=Json(new {entity_id=101,display_name="Synthetic User",netbios_name="EXAMPLE",sam_account_name="synthetic"}) };
    static JsonObject Nps(int id,int minute,int subject=101,string? ip="198.51.100.7",long? entity=null,int matches=0,int code=6273) => Json(new {
        event_db_id=id,event_record_id=10000+id,event_id=code,time_created_utc=$"2026-08-21T10:{minute:D2}:00Z",
        subject_user_sid=subject==0?null:Sid(subject),source_ip=ip,entity_id=entity,alias_match_count=matches,reason_code="16",source_core_sha256=new string('c',64)
    });
    static JsonObject Coverage(int failed=0,int success=0,int history=1) => Json(new {
        history_event_count=history,history_event_present=history>0,window_success_6272_count=success,window_failed_6273_count=failed
    });
    static JsonObject Observation(string id,string kind,int minute,char key='a') => Json(new {
        observation_id=id,lifecycle_event=kind,identity_state="exact",timestamp_state="ready",
        session_identity_key="radius-session:"+new string(key,64),exact_principal_key="entity:101",observed_at_utc=$"2026-08-21T09:{minute:D2}:00Z",
        evidence_uid=$"00000000-0000-0000-0000-{minute:D12}",source_instance_id="radius-source-7",stream_id="radius-accounting",
        transport_binding="windows-rpc-smb-readonly-tail-v1",object_reference=$"evidence:radius-{minute}",canonical_record_sha256=new string('a',64),
        object_sha256=new string('b',64),object_size_bytes=123,verified_at_utc=$"2026-08-21T09:{minute:D2}:00Z"
    });

    sealed class Store : IVpnStore,IVpnReadSession
    {
        internal readonly Dictionary<string,List<JsonObject>> Responses = new(StringComparer.Ordinal);
        internal readonly List<(string Sql,object?[] Values)> Calls = [];
        internal int Opens,Disposals;
        public Task<IVpnReadSession> OpenAsync(CancellationToken ct) { Opens++;return Task.FromResult<IVpnReadSession>(this); }
        public ValueTask DisposeAsync() { Disposals++;return ValueTask.CompletedTask; }
        public Task<List<JsonObject>> ReadAsync(string sql,object?[] parameters,CancellationToken ct)
        {
            Calls.Add((sql,parameters));
            if(sql.Contains("read_plugin_states_v1",StringComparison.Ordinal)) return Task.FromResult(new List<JsonObject> {Json(new {installed=true,enabled=true})});
            Assert.True(Responses.ContainsKey(sql),"Unexpected read: "+sql);
            return Task.FromResult(Responses[sql].Select(row=>(JsonObject)row.DeepClone()).ToList());
        }
    }

    [Fact]
    public async Task Evidence_drilldown_selects_only_requested_generation_and_hides_private_keys()
    {
        var store=new Store(); using var host=await VpnRouteTests.Host(store);
        using var response=await host.GetTestClient().GetAsync("/api/v1/reports/vpn.audit/sessions/evidence?domain_id=7&row_id=fixture",Ct);
        Assert.Equal(HttpStatusCode.ServiceUnavailable,response.StatusCode);
        var body=await response.Content.ReadAsStringAsync(Ct); Assert.Contains("module_disabled",body);
        Assert.DoesNotContain("exact_principal_key",body); Assert.DoesNotContain("session_identity_key",body); Assert.Empty(store.Calls);
    }

    [Fact]
    public async Task Closed_evidence_preserves_start_interim_stop_and_complete_manifest()
    {
        List<JsonObject> rows=[Observation("closed-start","start",1),Observation("closed-interim","interim_update",2),Observation("closed-stop","stop",3)];
        var store=new Store();store.Responses[VpnSql.Evidence]=rows;
        var result=await VpnSessions.Evidence(store,new(VpnRouteTests.MakeFacts()),Query with {RowId=RadiusSessionFold.Fold(rows)[0]["session_row_id"]!.ToString()},Ct);
        var observations=result["observations"]!.AsArray();
        Assert.Equal(new[]{"closed-start","closed-interim","closed-stop"},observations.Select(row=>row!["observation_id"]!.ToString()));
        Assert.Equal(new[]{"evidence:radius-1","evidence:radius-2","evidence:radius-3"},observations.Select(row=>row!["evidence"]!["object_reference"]!.ToString()));
        var stop=Json(new {evidence_uid="00000000-0000-0000-0000-000000000003",source_instance_id="radius-source-7",stream_id="radius-accounting",
            transport_binding="windows-rpc-smb-readonly-tail-v1",object_reference="evidence:radius-3",canonical_record_sha256=new string('a',64),object_sha256=new string('b',64),object_size_bytes=123,verified_at_utc="2026-08-21T09:03:00Z"});
        Assert.True(JsonNode.DeepEquals(new JsonArray(stop),result["lifecycle"]!["stop_evidence"]));
        Assert.Equal("complete",result["lifecycle"]!["completeness"]!.ToString());Assert.Null(result["lifecycle"]!["incomplete_reason"]);
    }

    [Fact]
    public void Timeline_orders_independent_Nps_facts_and_uses_history_presence_instead_of_count()
    {
        var denied=Nps(22,2,entity:101,matches:1);denied["correlation_id"]="source-native-nps-id";
        var result=VpnAuthorizations.Compose(Query,[denied,Nps(11,1,102,"198.51.100.8",code:6272),Nps(21,2,103,null,matches:2,code:6272)],Identities,Coverage(1,2),false);
        Assert.Equal("available",result["state"]!.ToString());
        var items=result["items"]!.AsArray();Assert.Equal(new[]{11,21,22},items.Select(row=>row!["event_db_id"]!.GetValue<int>()));
        Assert.Equal(new[]{6272,6272,6273},items.Select(row=>row!["event_id"]!.GetValue<int>()));
        Assert.Equal("allowed",items[0]!["authorization_result"]!.ToString());Assert.False(items[0]!.AsObject().ContainsKey("reason_code"));
        Assert.Equal("ambiguous",items[1]!["identity_state"]!.ToString());Assert.Equal(Sid(103),items[1]!["identity"]!["observed_subject_sid"]!.ToString());
        Assert.Equal("denied",items[2]!["authorization_result"]!.ToString());Assert.Equal("16",items[2]!["reason_code"]!.ToString());
        Assert.Equal("source-native-nps-id",items[2]!["correlation_id"]!.ToString());
        Assert.True(result["collection_coverage"]!["history_event_present"]!.GetValue<bool>());Assert.False(result["collection_coverage"]!.AsObject().ContainsKey("history_event_count"));
        Assert.DoesNotContain("session",result.ToJsonString().ToLowerInvariant());
    }

    [Fact]
    public void Empty_timeline_does_not_claim_verified_coverage()
    {
        var result=VpnAuthorizations.Compose(Query,[],[],Coverage(),false);
        Assert.Equal("coverage_unverified",result["state"]!.ToString());Assert.Empty(result["items"]!.AsArray());
        Assert.Equal("not_proven",result["collection_coverage"]!["source_completeness"]!.ToString());
    }

    [Theory]
    [InlineData(false,"2026-08-21T09:59:00Z")]
    [InlineData(true,"2026-08-21T09:59:00Z")]
    [InlineData(false,"2026-08-21T11:00:00Z")]
    [InlineData(true,"2026-08-21T11:00:00Z")]
    public void Nps_events_outside_inclusive_start_exclusive_end_are_rejected(bool series,string at)
    {
        var row=Nps(1,1);row["time_created_utc"]=at;
        Assert.Equal((series?"vpn_audit_failed_authorization":"vpn_audit_authorization_timeline")+"_event_outside_bounds",
            Assert.Throws<VpnInputException>(()=>VpnAuthorizations.Compose(Query,[row],[],Coverage(1),series)).Message);
    }

    [Fact]
    public void Timeline_rejects_input_beyond_reference_contract_bound()
    {
        var rows=Enumerable.Range(1,2001).Select(id=>Nps(id,1,code:6272)).ToList();
        Assert.Equal("vpn_audit_authorization_timeline_input_bound_exceeded",Assert.Throws<VpnInputException>(()=>VpnAuthorizations.Compose(Query,rows,[],Coverage(success:2001),false)).Message);
    }

    [Fact]
    public void Failed_series_keeps_identity_source_time_bounds_and_reference_truncation()
    {
        List<JsonObject> rows=[Nps(1,1,entity:101,matches:1),Nps(2,2,entity:101,matches:1),Nps(3,3,102),
            Nps(4,4,ip:"198.51.100.8",entity:101,matches:1),Nps(5,5,ip:null,entity:101,matches:1),Nps(6,6,103,matches:2)];
        var result=VpnAuthorizations.Compose(Query,rows,Identities,Coverage(6,history:6),true,eventReferenceLimit:1);
        var items=result["items"]!.AsArray().OfType<JsonObject>().ToArray();Assert.Equal(5,items.Length);
        var grouped=items.Single(row=>row["count"]!.GetValue<int>()==2);
        Assert.Equal("resolved",grouped["identity_state"]!.ToString());Assert.Equal("198.51.100.7",grouped["source_ip"]!.ToString());
        Assert.True(grouped["event_references_truncated"]!.GetValue<bool>());Assert.Single(grouped["event_references"]!.AsArray());
        Assert.Equal(1,grouped["event_references"]![0]!["event_db_id"]!.GetValue<int>());Assert.Equal(1,result["limits"]!["event_reference_limit"]!.GetValue<int>());
        Assert.Equal(Sid(102),items.Single(row=>row["identity_state"]!.ToString()=="unresolved")["identity"]!["observed_subject_sid"]!.ToString());
        Assert.Equal(Sid(103),items.Single(row=>row["identity_state"]!.ToString()=="ambiguous")["identity"]!["observed_subject_sid"]!.ToString());
        var missing=items.Single(row=>row["source_state"]!.ToString()=="unavailable");Assert.Equal(1,missing["count"]!.GetValue<int>());Assert.DoesNotContain("unknown",missing.ToJsonString().ToLowerInvariant());
        Assert.All(items,row=> {Assert.True(JsonNode.DeepEquals(result["time_bounds"],row["time_bounds"]));Assert.Equal(6273,row["event_id"]!.GetValue<int>());});
        foreach(string token in new[]{"attack","brute","spray","password"}) Assert.DoesNotContain(token,result.ToJsonString().ToLowerInvariant());
    }

    [Theory] [InlineData(0)] [InlineData(101)]
    public void Failed_series_rejects_invalid_reference_limit(int limit)
    {
        Assert.Equal("vpn_audit_failed_authorization_reference_limit_invalid",Assert.Throws<VpnInputException>(()=>VpnAuthorizations.Compose(Query,[],[],Coverage(history:0),true,eventReferenceLimit:limit)).Message);
    }

    [Fact]
    public void Missing_source_or_identity_never_creates_shared_failed_series()
    {
        var result=VpnAuthorizations.Compose(Query,[Nps(1,1,ip:null,entity:101,matches:1),Nps(2,2,ip:null,entity:101,matches:1),Nps(3,3,0),Nps(4,4,0)],Identities,Coverage(4,history:4),true);
        var items=result["items"]!.AsArray();Assert.Equal(4,items.Count);
        Assert.All(items,row=> {Assert.Equal("single_event_unattributed",row!["series_state"]!.ToString());Assert.Equal(1,row["count"]!.GetValue<int>());});
        Assert.Equal(new[]{1,2,3,4},items.Select(row=>row!["event_references"]![0]!["event_db_id"]!.GetValue<int>()).Order());
    }

    [Fact]
    public void Failed_series_rejects_successful_authorization_input()
    {
        Assert.Equal("vpn_audit_failed_authorization_event_invalid",Assert.Throws<VpnInputException>(()=>VpnAuthorizations.Compose(Query,[Nps(1,1,code:6272)],[],Coverage(1),true)).Message);
    }





    [Theory]
    [InlineData("domain_id=7&time_from=2026-08-21T10:00:00Z","windows_authentication_requires_time_bounds")]
    [InlineData(Bounds+"&limit=501","windows_authentication_limit_invalid")]
    public async Task Windows_route_rejects_missing_bounds_or_invalid_limit_before_event_reads(string query,string error)
    {
        var store=new Store(); using var host=await VpnRouteTests.Host(store);
        using var response=await host.GetTestClient().GetAsync("/api/v1/reports/vpn.audit/windows-authentication?"+query,Ct);
        Assert.Equal(HttpStatusCode.ServiceUnavailable,response.StatusCode); Assert.Empty(store.Calls);
        Assert.DoesNotContain(error,await response.Content.ReadAsStringAsync(Ct));
    }





    [Theory]
    [InlineData("sessions/evidence")] [InlineData("authorizations")]
    [InlineData("failed-authorizations/series")] [InlineData("windows-authentication")]
    public async Task Report_grant_without_required_branch_capability_never_reads_event_or_evidence_data(string operation)
    {
        var grant=JsonSerializer.SerializeToElement(new {report_key="vpn.audit",effect="allow",scope_json=new {kind="domain",ids=new[]{7}},
            field_categories=new[]{"identity_basic","security"},allowed_actions=new[]{"view"}});
        var facts=VpnRouteTests.MakeFacts(false) with {ReportAssignments=[grant]};
        if(operation=="sessions/evidence") facts=facts with {DirectCapabilities=[..facts.DirectCapabilities,JsonSerializer.SerializeToElement(new {
            capability_key="vpn.sessions.view",effect="allow",scope_json=new {kind="domain",ids=new[]{7}}})]};
        var access=new VpnAccess(facts);Assert.True(access.Report(7).Allowed);
        var store=new Store();
        var result=operation switch {
            "sessions/evidence"=>await VpnSessions.Evidence(store,access,Query with {RowId="radius-session-row:"+new string('a',64)},Ct),
            "windows-authentication"=>await VpnWindows.Read(store,access,Query,Ct),
            _=>await VpnAuthorizations.Read(store,access,Query,operation=="failed-authorizations/series",Ct)
        };
        Assert.Equal("not_authorized",result["state"]!.ToString());Assert.Empty(store.Calls);
        Assert.Empty(result[operation=="sessions/evidence"?"observations":"items"]!.AsArray());
    }

    [Fact]
    public async Task Postgres_read_session_establishes_read_only_repeatable_snapshot_before_first_read()
    {
        var store=new PostgresVpnStore(null!);
        var error=await Assert.ThrowsAsync<InvalidOperationException>(()=>store.OpenAsync(Ct));
        Assert.Equal("module_disabled",error.Message);
    }
}
