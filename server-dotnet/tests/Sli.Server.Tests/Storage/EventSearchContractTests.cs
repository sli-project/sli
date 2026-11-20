using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Access;
using Sli.Server.Storage.EventReports;
using Xunit;
namespace Sli.Server.Tests.Storage;

public sealed class EventSearchContractTests
{
    [Fact]
    public void Round2V1ListProjectionDoesNotReleaseExactEvidence()
    {
        var projected = EventListProjection.Project(Compatibility.LegacyProjectionTests.Round2RawEvent());
        Compatibility.LegacyProjectionTests.AssertRound2SummaryOnly(new JsonObject { ["items"] = new JsonArray(projected) });
        Assert.Equal(17, projected["event_db_id"]!.GetValue<long>());
    }

    static readonly DateTimeOffset Now=DateTimeOffset.Parse("2026-11-05T12:00:00Z");
    static EventSearchInput Input(string extra="")=>EventSearchInput.Parse(JsonNode.Parse("{\"contract_version\":\"evsearch.v1\""+extra+"}")!.AsObject(),Now);
    static EventSearchPolicy Policy(EventSearchInput input)
    { var facts=EventQueryEndpointTests.MakeFacts(); return EventSearchPolicy.Authorize(facts,new ReportEligibility().Compose(facts,new CapabilityComposer().Compose(facts)),input); }
    [Fact] public void Frozen_snapshot_contains_only_published_projections()
    {
        var input=Input(); var policy=Policy(input); var runtime=new EventSearchRuntime(TimeProvider.System);
        var fields=JsonNode.Parse("{\"id\":1,\"event_id\":4625,\"channel\":\"Security\",\"time_created_utc\":\"2026-11-05T11:00:00Z\"}")!.AsObject();
        string id=runtime.Start(1,input,policy,[new(1,Now.AddHours(-1),new string('A',64),"postgres",fields)],Now.AddDays(-7),TestContext.Current.CancellationToken);
        var page=runtime.Page(id,runtime.Get(id,1),new JsonObject(),false); Assert.Single(page["items"]!.AsArray());
        // Byte-exact hashlib/json.dumps values from the Python contract.
        Assert.Equal("d2a2931b25a18328e05255602d74619b4a618c6a1f446bc3a11bfa63326cce6c",page["items"]![0]!["group_key"]!.ToString());
        Assert.Equal("27cd6272a84aece360f3388adfcc1810ff1136e4540d4ebb97ad94339a9826bf",page["query_hash"]!.ToString());
    }
    [Theory]
    [InlineData(",\"page_size\":101","invalid_request")]
    [InlineData(",\"page_size\":true","invalid_request")]
    [InlineData(",\"scope\":{\"kind\":\"all\"}","invalid_request")]
    [InlineData(",\"conditions\":[{\"field\":\"event_id\",\"operator\":\"eq\",\"value\":4625}]","event_context_required")]
    [InlineData(",\"conditions\":[{\"field\":\"account\",\"operator\":\"eq\",\"value\":1}]","invalid_condition")]
    [InlineData(",\"conditions\":[{\"field\":\"channel\",\"operator\":\"contains\",\"value\":\"Security\"}]","unsupported_operator")]
    [InlineData(",\"conditions\":[{\"field\":\"no_such_field\",\"operator\":\"eq\",\"value\":\"x\"}]","unsupported_field")]
    [InlineData(",\"conditions\":[{\"field\":\"channel\",\"operator\":\"missing\",\"value\":\"x\"}]","invalid_condition")]
    [InlineData(",\"period\":{\"preset\":\"custom\",\"from\":\"2026-01-01\",\"to\":\"2026-11-05\",\"timezone\":\"UTC\"}","period_too_wide")]
    [InlineData(",\"period\":{\"preset\":\"custom\",\"from\":\"2026-11-06\",\"to\":\"2026-11-04\",\"timezone\":\"UTC\"}","invalid_period")]
    [InlineData(",\"entry_context\":{\"kind\":\"entity\",\"return_to\":\"//attacker.example\"}","invalid_request")]
    public void Rejects_invalid_contract_without_io(string extra,string code)
    { Assert.Equal("evsearch."+code,Assert.Throws<EventSearchException>(()=>Input(extra)).Code); }
    [Fact] public void Normalization_uses_elapsed_utc_and_inclusive_local_date_end()
    {
        var relative=Input(); Assert.Equal(Now.AddDays(-1),relative.From); Assert.Equal(Now,relative.To);
        var custom=Input(",\"period\":{\"preset\":\"custom\",\"from\":\"2026-11-01\",\"to\":\"2026-11-02\",\"timezone\":\"Asia/Bangkok\"}");
        Assert.Equal(DateTimeOffset.Parse("2026-10-31T17:00:00Z"),custom.From); Assert.Equal(DateTimeOffset.Parse("2026-11-02T17:00:00Z"),custom.To);
    }
    [Fact] public void Last_selection_wins_and_null_retaining_exclusion_is_compiled()
    {
        var input=Input(",\"conditions\":[{\"field\":\"channel\",\"operator\":\"eq\",\"value\":\"Security\"},{\"field\":\"channel\",\"operator\":\"not_in\",\"value\":[\"Security\"]}]");
        var c=Assert.Single(input.Conditions); Assert.Equal("not_in",c.Operator); var sql=new EventSearchSql(); string predicate=sql.Condition(c); Assert.Contains("is null",predicate); Assert.DoesNotContain("Security",predicate); Assert.Contains("Security",sql.Parameters.Values);
    }
    [Fact] public void User_values_cannot_become_sql_and_short_rows_get_scope_before_rows()
    {
        var input=Input(",\"conditions\":[{\"field\":\"channel\",\"operator\":\"eq\",\"value\":\"x' OR 1=1 --\"}]"); var policy=Policy(input);
        var pg=new EventSearchSql(); string hot=pg.Predicate(input,policy); Assert.DoesNotContain("x' OR",hot); Assert.Contains("e.domain_id",hot); Assert.Contains(1L,pg.Parameters.Values);
    }
    [Fact] public void Unknown_scope_dimension_fails_closed()
    {
        var sql=new EventSearchSql(); using var doc=JsonDocument.Parse("{\"mode\":\"restricted\",\"clauses\":[{\"plugin_ids\":[\"p\"]}]}");
        Assert.Equal("evsearch.policy_denied",Assert.Throws<EventSearchException>(()=>sql.Scope([doc.RootElement])).Code);
    }
    [Fact] public void Stable_participant_exclusion_matches_any_selected_role()
    {
        var input=Input(",\"conditions\":[{\"field\":\"account\",\"operator\":\"not_in\",\"role\":\"target\",\"value\":[2]}]");
        var fields=JsonNode.Parse("{\"account\":[{\"entity_id\":1,\"role\":\"target\"},{\"entity_id\":2,\"role\":\"target\"}]}")!.AsObject(); Assert.False(EventSearchProjection.MatchesLinks(input,fields));
        fields=JsonNode.Parse("{\"account\":[{\"entity_id\":2,\"role\":\"actor\"}]}")!.AsObject(); Assert.True(EventSearchProjection.MatchesLinks(input,fields));
    }
    [Fact] public void Unresolved_events_stay_singletons_even_with_equal_display_fields()
    {
        var fields=JsonNode.Parse("{\"event_id\":4625,\"channel\":\"Security\",\"group_identity_complete\":false}")!.AsObject();
        Assert.NotEqual(EventSearchProjection.GroupKey(new(1,Now,"","postgres",fields)),EventSearchProjection.GroupKey(new(2,Now,"","clickhouse",fields)));
    }
    [Fact] public void Categories_from_separate_grants_cannot_be_combined()
    {
        var facts=EventQueryEndpointTests.MakeFacts();
        JsonElement Grant(string category)=>EventQueryEndpointTests.Json(new {report_key="events.explorer",effect="allow",scope_json=new {kind="domain",ids=new[]{1}},field_categories=new[]{category},allowed_actions=new[]{"view"}});
        facts=facts with {ReportAssignments=[Grant("technical"),Grant("security")]};
        var caps=new CapabilityComposer().Compose(facts);
        Assert.Equal("evsearch.policy_denied",Assert.Throws<EventSearchException>(()=>EventSearchPolicy.Authorize(facts,new ReportEligibility().Compose(facts,caps),Input())).Code);
    }
    [Fact] public void Unpublished_dataset_cannot_be_read_even_with_report_assignment()
    {
        var facts=EventQueryEndpointTests.MakeFacts(); var definition=JsonNode.Parse(facts.Definitions[0].GetRawText())!.AsObject(); definition["dataset_status"]="retired";
        facts=facts with {Definitions=[JsonSerializer.SerializeToElement(definition)]}; var caps=new CapabilityComposer().Compose(facts);
        Assert.Equal("evsearch.policy_denied",Assert.Throws<EventSearchException>(()=>EventSearchPolicy.Authorize(facts,new ReportEligibility().Compose(facts,caps),Input())).Code);
    }
    static JsonObject Logon()=>JsonNode.Parse("""
        {"id":1,"time_created_utc":"2026-11-05T11:00:00Z","action":"authentication.logon","provider":"Microsoft-Windows-Security-Auditing","channel":"Security","event_id":4625,
         "outcome":"failure","reason":"0xc000006a","logon_type":"3","account":[{"entity_id":12,"role":"actor"},{"entity_id":13,"role":"target"}],
         "source_station":[20],"ip":"192.0.2.1","related_object":[12,13,20],"server_id":5,"domain_id":1,"task_identity":null,"process_identity":null,"file_identity":null,"group_identity_complete":false,"title":"Failed logon"}
        """)!.AsObject();
    [Fact] public void Confirmed_native_logons_group_and_member_pages_have_no_gaps()
    {
        var a=Logon(); EventSearchProjection.Complete(a); Assert.True(a["group_identity_complete"]!.GetValue<bool>());
        var b=(JsonObject)a.DeepClone(); b["id"]=2L; b["time_created_utc"]="2026-11-05T11:30:00Z";
        var input=Input(",\"page_size\":1"); var policy=Policy(input); var runtime=new EventSearchRuntime(TimeProvider.System);
        string id=runtime.Start(1,input,policy,[new(1,Now.AddHours(-1),new string('A',64),"postgres",a),new(2,Now.AddMinutes(-30),new string('B',64),"clickhouse",b)],Now.AddDays(-7),TestContext.Current.CancellationToken);
        var entry=runtime.Get(id,1); var groups=runtime.Page(id,entry,new JsonObject(),false); Assert.Single(groups["items"]!.AsArray()); Assert.Equal(2,groups["items"]![0]!["count"]!.GetValue<int>()); Assert.NotNull(groups["items"]![0]!["fields"]!["title"]);
        var req=new JsonObject { ["group_key"]=groups["items"]![0]!["group_key"]!.DeepClone() };
        var first=runtime.Page(id,entry,req,true); Assert.True(first["has_more"]!.GetValue<bool>()); Assert.Equal(1,first["items"]![0]!["event_db_id"]!.GetValue<long>());
        req["cursor"]=first["next_cursor"]!.DeepClone(); var second=runtime.Page(id,entry,req,true); Assert.False(second["has_more"]!.GetValue<bool>()); Assert.Equal(2,second["items"]![0]!["event_db_id"]!.GetValue<long>());
    }
    [Fact] public void Summary_counts_distinct_events_per_value_and_histogram_conserves_total()
    {
        var input=Input(); var policy=Policy(input); var runtime=new EventSearchRuntime(TimeProvider.System);
        var a=JsonNode.Parse("{\"id\":1,\"event_id\":4625,\"channel\":\"Security\",\"related_object\":[10,11]}")!.AsObject();
        var b=JsonNode.Parse("{\"id\":2,\"event_id\":4625,\"channel\":\"Security\",\"related_object\":[11]}")!.AsObject();
        string id=runtime.Start(1,input,policy,[new(1,Now.AddHours(-1),new string('A',64),"postgres",a),new(2,Now.AddMinutes(-30),new string('B',64),"clickhouse",b)],Now.AddDays(-7),TestContext.Current.CancellationToken);
        var result=runtime.Summary(id,runtime.Get(id,1),new JsonObject { ["facet_field"]="related_object",["page_size"]=1,["blocks"]=new JsonArray(JsonValue.Create("totals"),JsonValue.Create("facets"),JsonValue.Create("histogram"),JsonValue.Create("coverage")),["histogram_buckets"]=2 },policy,TestContext.Current.CancellationToken);
        var facet=result["facets"]!["related_object"]!; Assert.Equal(11,facet["items"]![0]!["value"]!.GetValue<int>()); Assert.Equal(2,facet["items"]![0]!["count"]!.GetValue<int>()); Assert.Equal(1,facet["other_events_count"]!.GetValue<int>()); Assert.True(facet["multi_valued"]!.GetValue<bool>());
        Assert.Equal(2,result["histogram"]!["items"]!.AsArray().Sum(n=>n!["value"]!.GetValue<int>())); Assert.Equal("unknown",result["source_coverage"]!["status"]!.ToString());
        var next=runtime.Summary(id,runtime.Get(id,1),new JsonObject { ["facet_field"]="related_object",["cursor"]=facet["next_cursor"]!.DeepClone(),["page_size"]=1 },policy,TestContext.Current.CancellationToken); Assert.Equal(10,next["facets"]!["related_object"]!["items"]![0]!["value"]!.GetValue<int>());
    }
    [Fact] public void List_projection_preserves_catalog_context_and_never_releases_raw_data()
    {
        var row=JsonNode.Parse("{\"id\":1,\"event_id\":4724,\"server\":\"dc1\",\"channel\":\"Security\",\"provider_name\":\"Microsoft-Windows-Security-Auditing\",\"time_created_utc\":\"2026-11-05T11:00:00Z\",\"subject_user_name\":\"private-name\",\"message_text\":\"private-payload\"}")!.AsObject();
        var projected=EventListProjection.Project(row); Assert.Equal("Попытка сброса пароля",projected["label"]!.ToString()); Assert.Equal("high",projected["base_risk"]!.ToString()); Assert.Equal("account_management",projected["category"]!.ToString()); Assert.DoesNotContain("private-",projected.ToJsonString());
        row["provider_name"]="unrelated.provider"; projected=EventListProjection.Project(row); Assert.False(projected["catalog_match"]!.GetValue<bool>()); Assert.Equal("unknown",projected["final_security_severity"]!.ToString());
    }
}
