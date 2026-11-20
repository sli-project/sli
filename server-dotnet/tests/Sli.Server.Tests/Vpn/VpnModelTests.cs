using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Sli.Server.Access;
using Sli.Server.Vpn;
using Xunit;

namespace Sli.Server.Tests.Vpn;

public sealed class VpnModelTests
{
    static JsonObject Json(object value)=>VpnRouteTests.Json(value);
    static VpnQuery Query=>new(1,"view","UTC",DateTimeOffset.Parse("2026-01-01T00:00:00Z"),DateTimeOffset.Parse("2026-01-02T00:00:00Z"),200,0,"");
    [Fact] public void Nps_and_Windows_JSON_match_pure_Python_reference_composers()
    {
        using var stream=typeof(VpnModelTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Vpn.report-reference.json")!;
        foreach(var vector in JsonNode.Parse(stream)!.AsArray())
        {
            string kind=vector!["kind"]!.ToString();var rows=vector["events"]!.AsArray().OfType<JsonObject>().ToList();var coverage=vector["coverage"]!.AsObject();JsonObject actual;
            if(kind=="windows") actual=VpnWindows.Compose(Query,rows,coverage,vector["policy"]!.AsObject(),false);
            else actual=VpnAuthorizations.Compose(Query,rows,vector["identities"]!.AsArray().OfType<JsonObject>().ToDictionary(r=>r["entity_id"]!.GetValue<long>()),coverage,kind=="series");
            Assert.True(JsonNode.DeepEquals(vector["expected"],actual),kind+": "+actual.ToJsonString());
        }
    }
    [Fact] public void Fold_matches_eight_Python_reference_vectors_including_restart_and_reordering()
    {
        using var stream=typeof(VpnModelTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Vpn.fold-reference.json")!;
        var vectors=JsonNode.Parse(stream)!.AsArray();Assert.Equal(8,vectors.Count);
        foreach(var vector in vectors)
        {
            var actual=JsonSerializer.SerializeToNode(RadiusSessionFold.Fold(vector!["inputs"]!.AsArray().OfType<JsonObject>()))!;
            Assert.True(JsonNode.DeepEquals(vector["expected"],actual),vector["name"]+": "+actual.ToJsonString());
        }
    }
    [Fact] public void Fold_fails_closed_on_duplicate_conflicting_or_unresolved_keys()
    {
        var rows=VpnRouteTests.Observations();rows.Add((JsonObject)rows[0].DeepClone());Assert.Equal("duplicate_observation_id",Assert.Throws<VpnInputException>(()=>RadiusSessionFold.Fold(rows)).Message);
        rows=VpnRouteTests.Observations();rows[1]["exact_principal_key"]="another-principal";Assert.Equal("session_key_principal_conflict",Assert.Throws<VpnInputException>(()=>RadiusSessionFold.Fold(rows)).Message);
        rows=VpnRouteTests.Observations();rows[0]["identity_state"]="unresolved";Assert.Equal("unresolved_identity_has_exact_keys",Assert.Throws<VpnInputException>(()=>RadiusSessionFold.Fold(rows)).Message);
        rows=VpnRouteTests.Observations();rows[0]["canonical_record_sha256"]="invalid";Assert.Equal("evidence_sha256_invalid",Assert.Throws<VpnInputException>(()=>RadiusSessionFold.Fold(rows)).Message);
    }
    [Theory] [InlineData(0,0,0,0,"not_collected")] [InlineData(1,1,0,1,"processing")] [InlineData(1,0,1,0,"identity_incomplete")] [InlineData(2,0,1,1,"partial")] [InlineData(2,0,0,1,"available")]
    public void Coverage_preserves_pipeline_states(int total,int pending,int unresolved,int sessions,string expected)
    {Assert.Equal(expected,VpnSessions.CoverageState(Json(new {total_delivery_count=total,queued_delivery_count=pending,identity_unresolved_count=unresolved,projected_session_count=sessions})));}
    [Fact] public void Time_range_handles_local_dates_offsets_DST_and_bounds()
    {
        var (from,to)=VpnQuery.Range("2026-01-01","2026-01-01","Asia/Bangkok");Assert.Equal(DateTimeOffset.Parse("2025-12-31T17:00:00Z"),from);Assert.Equal(TimeSpan.FromDays(1),to-from);
        Assert.Equal("ambiguous_local_datetime_requires_offset",Assert.Throws<VpnInputException>(()=>VpnQuery.Range("2026-11-01T01:30:00","","America/New_York")).Message);
        Assert.Equal("nonexistent_local_datetime",Assert.Throws<VpnInputException>(()=>VpnQuery.Range("2026-03-08T02:30:00","","America/New_York")).Message);
        Assert.Equal("invalid_timezone",Assert.Throws<VpnInputException>(()=>VpnQuery.Range("","","synthetic/invalid")).Message);
        Assert.Equal("empty_or_reversed_time_range",Assert.Throws<VpnInputException>(()=>VpnQuery.Range("2026-01-02T00:00:00Z","2026-01-01T00:00:00Z","UTC")).Message);
    }
    [Fact] public void Atomic_report_scope_and_explicit_capability_deny_do_not_leak_adjacent_domains()
    {
        var initial=VpnRouteTests.MakeFacts(false);
        var caps=new[]{"reports.catalog","vpn.sessions.view","vpn.session.evidence.read","events.view","field.identity_basic","field.security"}.Select(c=>JsonSerializer.SerializeToElement(new {capability_key=c,effect="allow",scope_json=new {kind="domain",ids=new[]{1}}})).ToArray();
        var grant=JsonSerializer.SerializeToElement(new {report_key="vpn.audit",effect="allow",scope_json=new {kind="domain",ids=new[]{1}},field_categories=new[]{"identity_basic","security"},allowed_actions=new[]{"view"}});
        var access=new VpnAccess(initial with {DirectCapabilities=caps,ReportAssignments=[grant]});Assert.True(access.Branch("sessions",1).Allowed);Assert.False(access.Branch("sessions",2).Allowed);Assert.True(access.Windows(1));Assert.False(access.Windows(2));
        var deny=JsonSerializer.SerializeToElement(new {capability_key="vpn.sessions.view",effect="deny",scope_json=new {kind="domain",ids=new[]{1}}});
        access=new VpnAccess(initial with {DirectCapabilities=[..caps,deny],ReportAssignments=[grant]});Assert.False(access.Branch("sessions",1).Allowed);Assert.Equal("explicit_deny",access.Branch("sessions",1).reason);
        Assert.False(access.Branch("sessions",1,"export").Allowed);
    }
    [Fact] public void Nps_unknown_identity_or_source_never_forms_invented_series()
    {
        List<JsonObject> rows=Enumerable.Range(1,3).Select(i=>Json(new {event_db_id=i,event_id=6273,time_created_utc=$"2026-01-01T00:0{i}:00Z",subject_user_sid=(string?)null,source_ip="192.0.2.9",reason_code="16"})).ToList();
        var coverage=Json(new {history_event_count=3,window_failed_6273_count=3,window_success_6272_count=0});
        var data=VpnAuthorizations.Compose(Query,rows,[],coverage,true);Assert.Equal(3,data["items"]!.AsArray().Count);Assert.All(data["items"]!.AsArray(),row=>Assert.Equal("single_event_unattributed",row!["series_state"]!.ToString()));
        foreach(var row in rows) row["subject_user_sid"]="S-1-5-21-100000001-200000002-300000003-7";
        data=VpnAuthorizations.Compose(Query,rows,[],coverage,true);Assert.Single(data["items"]!.AsArray());Assert.Equal(3,data["items"]![0]!["count"]!.GetValue<int>());
        Assert.DoesNotContain("session_row_id",data.ToJsonString());
    }
    [Fact] public void Nps_empty_coverage_and_count_mismatch_are_distinct()
    {
        var data=VpnAuthorizations.Compose(Query,[],[],Json(new {history_event_count=1,window_failed_6273_count=0,window_success_6272_count=1}),true);Assert.Equal("empty_unverified",data["state"]!.ToString());
        data=VpnAuthorizations.Compose(Query,[],[],Json(new {history_event_count=1,window_failed_6273_count=0,window_success_6272_count=0}),true);Assert.Equal("coverage_unverified",data["state"]!.ToString());
        Assert.Equal("vpn_audit_failed_authorization_collection_coverage_mismatch",Assert.Throws<VpnInputException>(()=>VpnAuthorizations.Compose(Query,[],[],Json(new {history_event_count=1,window_failed_6273_count=1}),true)).Message);
    }
    [Fact] public void Windows_mixed_result_unknown_is_not_failure_and_earlier_failures_are_sample_only()
    {
        var rows=new[]{(1,4625,"16"),(2,4776,""),(3,4624,"")}.Select(x=>Json(new {event_db_id=x.Item1,event_id=x.Item2,time_created_utc=$"2026-01-01T00:0{x.Item1}:00Z",domain_controller="dc.example.test",target_user_sid="S-1-5-21-100000001-200000002-300000003-7",source_ip="192.0.2.7",result_code=x.Item3})).ToList();
        var result=VpnWindows.Compose(Query,rows,Json(new {history_event_present=true}),Json(new {state="no_observed_signal_unverified"}),false);
        Assert.Equal("unknown",result["items"]![1]!["outcome"]!["state"]!.ToString());Assert.Single(result["items"]![2]!["earlier_observed_failures_in_window"]!["event_references"]!.AsArray());
        rows[1]["event_id"]=4672;rows[1]["subject_user_name"]="synthetic-subject";result=VpnWindows.Compose(Query,rows,Json(new {history_event_present=true}),new JsonObject(),false);Assert.Equal("subject_account",result["items"]![1]!["principal"]!["role"]!.ToString());
    }
    [Fact] public void Windows_review_uses_whole_period_and_excludes_over_cap_accounts()
    {
        var failures=Enumerable.Range(0,6).Select(i=>Json(new {id=i+1,at=$"2026-01-01T00:0{i}:00Z",sid="synthetic-sid-"+(i%3),ip="192.0.2.7",source="ip:192.0.2.7"})).ToList();
        var review=VpnWindows.Review(failures,Query);Assert.Equal("whole_period",review["coverage_scope"]!.ToString());Assert.Single(review["signals"]!.AsArray());Assert.True(review["not_a_verdict"]!.GetValue<bool>());
        foreach(var row in failures) row["at"]="2026-01-01T00:00:00Z";
        review=VpnWindows.Review(failures,Query,24,3,1,1);Assert.DoesNotContain(review["signals"]!.AsArray(),s=>s!["rule"]!.ToString()=="distributed");
    }
    [Fact] public void Confirmed_time_is_unioned_and_open_session_time_is_unknown()
    {
        var closed=(JsonObject)RadiusSessionFold.Fold(VpnRouteTests.Observations())[0].DeepClone();closed["entity_id"]=7;closed["domain_id"]=1;
        var overlap=(JsonObject)closed.DeepClone();overlap["session_row_id"]="another-session";
        var open=(JsonObject)closed.DeepClone();open["session_row_id"]="open-session";open["entity_id"]=8;open["stopped_at_utc"]=null;open["duration_seconds"]=null;open["completeness"]="missing_stop";
        var raw=VpnConnections.Compose(Query,[closed,overlap,open],[],[],Json(new {total_delivery_count=3,projected_session_count=3}),TimeZoneInfo.Utc);
        var employees=raw["employees"]!.AsArray();Assert.Equal(120,employees[0]!["confirmed_seconds"]!.GetValue<long>());Assert.True(employees[0]!["overlap_violation"]!.GetValue<bool>());Assert.Null(employees[1]!["confirmed_seconds"]);
        var pairs=VpnOverlap.Analyze([closed,overlap,open],Query);Assert.Single(pairs["items"]!.AsArray());Assert.Equal(120,pairs["metrics"]!["confirmed_seconds"]!.GetValue<long>());
    }
    [Fact] public void Account_fields_stay_absent_and_cursor_and_csv_are_bounded()
    {
        var row=Json(new {object_id="7",display_name="=synthetic"});VpnAccounts.Present(row,null);Assert.False(row.ContainsKey("department"));Assert.Equal("unavailable",row["department_text_code"]!.ToString());
        Assert.Equal(7,VpnAccounts.DecodeCursor(VpnAccounts.EncodeCursor("7")));Assert.Throws<VpnInputException>(()=>VpnAccounts.DecodeCursor("invalid"));
        var result=VpnReports.Result("vpn.accounts","ok",[row]);result["_export_fields"]=new JsonArray(Json(new {key="display_name",label="Пользователь"}));Assert.Contains("'=synthetic",VpnReports.Csv(result,null));Assert.DoesNotContain("department",VpnReports.Csv(result,null));
    }
    [Fact] public void Policy_denials_use_latest_facts_and_truncated_growth_stays_unknown()
    {
        var row=Json(new {source_event_id=7,normalized_event_id="synthetic-event",occurred_at_utc="2026-01-01T00:01:00Z",semantic_type="remote_access.authentication.denied",facts_json=new {network_policy="Synthetic",reason_code="16"},roles_json=new {affected_entity="synthetic-account"},quality_json=new {identity_roles=new {affected_entity=new {state="resolved",provisional=false}}}});
        var result=VpnPolicyDenials.Compose([row],[],Query.From!.Value,Query.To!.Value,false,true);Assert.Null(result["items"]![0]!["growth"]);Assert.Equal(1,result["metrics"]!["affected_accounts"]!.GetValue<int>());
        Assert.Equal("nps_policy_duplicate_source_event",Assert.Throws<VpnInputException>(()=>VpnPolicyDenials.Compose([row,row],[],Query.From.Value,Query.To.Value)).Message);
    }
}
