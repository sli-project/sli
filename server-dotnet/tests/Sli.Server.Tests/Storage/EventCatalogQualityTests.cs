using System.Text.Json.Nodes;
using Sli.Server.Storage.EventReports;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class EventCatalogQualityTests
{
    static JsonObject Object(string json)=>JsonNode.Parse(json)!.AsObject();
    static JsonObject Catalog()=>EventCatalogQuality.ShippedCatalog();
    static JsonObject WithEntries(params JsonObject[] entries)=>new() { ["entries"]=new JsonArray(entries.Select(e=>(JsonNode)e.DeepClone()).ToArray()) };
    static string[] Codes(JsonObject result)=>result["errors"]!.AsArray().Select(e=>e!["code"]!.ToString()).ToArray();
    static KnownBundleNormalizer Normalizer()=>new(EventCardSemanticsTests.Repository(),null,null);

    [Fact] public async Task Shipped_catalog_validates_log_full_and_dns_timeout_are_known_and_task_203_is_unknown()
    {
        var result=EventCatalogQuality.ValidateCatalogData(Catalog());
        Assert.True((bool)result["valid"]!,result["errors"]!.ToJsonString());
        var normalizer=Normalizer();
        var logFull=await normalizer.CardAsync(Object("""{"event_id":1104,"channel":"Security","provider_name":"Microsoft-Windows-Eventlog"}"""),TestContext.Current.CancellationToken);
        Assert.True((bool)logFull["catalog_match"]!); Assert.Equal("critical",logFull["severity"]!.ToString());
        var dns=await normalizer.CardAsync(Object("""{"event_id":4016,"channel":"DNS Server","provider_name":"Microsoft-Windows-DNS-Server-Service"}"""),TestContext.Current.CancellationToken);
        Assert.True((bool)dns["catalog_match"]!); Assert.Equal("medium",dns["severity"]!.ToString()); Assert.Equal("important",dns["purpose_tier"]!.ToString());
        var unknown=await normalizer.CardAsync(Object("""{"event_id":203,"channel":"Microsoft-Windows-TaskScheduler/Operational","provider_name":"Microsoft-Windows-TaskScheduler"}"""),TestContext.Current.CancellationToken);
        Assert.False((bool)unknown["catalog_match"]!); Assert.Equal("unknown",unknown["final_security_severity"]!.ToString());
    }

    [Fact] public void Service_install_descriptor_is_exact_and_does_not_claim_an_actor_or_causation()
    {
        var descriptor=Catalog()["entries"]!.AsArray().Single(e=>e!["channel"]?.ToString()=="System" && e["event_id"]?.ToString()=="7045")!;
        foreach(var (key,expected) in new[]{("provider_name","Service Control Manager"),("severity","info"),("purpose_tier","important"),("noise_class","signal"),("category","operations")}) Assert.Equal(expected,descriptor[key]!.ToString());
        var fields=descriptor["required_fields"]!.AsArray().Select(n=>n!.ToString()).ToHashSet();
        foreach(string field in new[]{"event_id","time_created_utc","server_id","event_record_id","source_core_sha256","source_facts_sha256","service_name","service_file","service_account","service_start_type"}) Assert.Contains(field,fields);
        foreach(string field in new[]{"process_user_sid","process_user_name","process_user_domain","process_logon_id"}) Assert.DoesNotContain(field,fields);
        Assert.Contains("time",descriptor["correlation_absent_reason"]!.ToString()); Assert.Contains("name",descriptor["correlation_absent_reason"]!.ToString());
    }

    [Fact] public void Validator_rejects_duplicate_identity_invalid_severity_role_and_pivot()
    {
        var entry=Object("""{"channel":"Fixture","event_id":1,"provider_name":"Provider","severity":"medium","card":{"field_roles":{"object":["ObjectName"]}}}""");
        var invalid=(JsonObject)entry.DeepClone(); invalid["severity"]="extreme"; invalid["card"]=Object("""{"field_roles":{"magic":["bad field"]}}""");
        var result=EventCatalogQuality.ValidateCatalogData(WithEntries(entry,invalid));
        Assert.False((bool)result["valid"]!); var codes=Codes(result);
        foreach(string code in new[]{"duplicate_identity","invalid_severity","invalid_field_role","invalid_field_pivot"}) Assert.Contains(code,codes);
        var duplicate=result["errors"]!.AsArray().Single(e=>e!["code"]!.ToString()=="duplicate_identity")!;
        Assert.Equal(1,(int)duplicate["index"]!); Assert.Equal(0,(int)duplicate["first_index"]!);
    }

    [Theory] [InlineData("infrastructure")] [InlineData("infra")]
    public void Infrastructure_category_is_canonical_and_unknown_categories_are_rejected(string category)
    {
        var entry=Object("""{"channel":"Fixture","event_id":2,"provider_name":"Provider","severity":"info","category":"infrastructure","card":{}}""");
        Assert.True((bool)EventCatalogQuality.ValidateCatalogData(WithEntries(entry))["valid"]!);
        entry["category"]=category;
        Assert.Equal("infrastructure",EventCardSemantics.Build(new JsonObject(),entry,null)["category"]!.ToString());
        entry["category"]="invented";
        Assert.Contains("invalid_category",Codes(EventCatalogQuality.ValidateCatalogData(WithEntries(entry))));
    }

    [Fact] public void Coverage_is_weighted_payload_free_and_unknowns_are_returned_as_gaps()
    {
        var rows=new[]{Object("""{"channel":"Security","event_id":4720,"provider_name":"Microsoft-Windows-Security-Auditing","count":9}"""),Object("""{"channel":"Fixture","event_id":999999,"provider_name":"Unknown","count":1,"message_text":"must-not-leak"}""")};
        var result=EventCatalogQuality.CoverageSummary(rows,Catalog()["entries"]!.AsArray().OfType<JsonObject>());
        Assert.Equal(1,(int)result["groups_covered"]!); Assert.Equal(0.9,(double)result["event_coverage_ratio"]!); Assert.Equal(1,(int)result["gap_count"]!);
        Assert.False((bool)result["contains_event_payload"]!); Assert.DoesNotContain("message_text",result.ToJsonString()); Assert.DoesNotContain("must-not-leak",result.ToJsonString());
        Assert.True(JsonNode.DeepEquals(Object("""{"channel":"Fixture","event_id":999999,"provider_name":"Unknown","count":1,"first_seen":null,"last_seen":null}"""),result["gaps"]![0]));
        var empty=EventCatalogQuality.CoverageSummary([],[]); Assert.Equal(1,(double)empty["event_coverage_ratio"]!); Assert.Equal(1,(double)empty["group_coverage_ratio"]!);
    }

    [Fact] public void Fixture_promotion_requires_field_evidence_and_never_mutates_catalog_or_fixture()
    {
        var fixture=Object("""{"channel":"Fixture","event_id":9001,"provider_name":"Fixture-Provider","verified_semantics":{"severity":"low","title":"Fixture action","why":"Verified","fix":"Inspect","missing":"Field"}}""");
        var catalog=Catalog(); string before=catalog.ToJsonString();
        Assert.Equal("field_level_evidence_required",Assert.Throws<ArgumentException>(()=>EventCatalogQuality.ProposeCatalogPromotion(catalog,fixture)).Message);
        fixture["evidence_fields"]=new JsonArray("ObjectName"); string fixtureBefore=fixture.ToJsonString();
        var proposal=EventCatalogQuality.ProposeCatalogPromotion(catalog,fixture);
        Assert.Equal("proposed",proposal["status"]!.ToString()); Assert.False((bool)proposal["writes_performed"]!);
        Assert.Equal("low",proposal["entry"]!["severity"]!.ToString()); Assert.Equal(new[]{"ObjectName"},proposal["evidence_fields"]!.AsArray().Select(n=>n!.ToString()));
        Assert.Equal(before,catalog.ToJsonString()); Assert.Equal(fixtureBefore,fixture.ToJsonString());
    }

    [Theory] [InlineData("cmd.exe /c whoami","high")] [InlineData("powershell.exe -File fixture.ps1","high")] [InlineData("fixture.exe","medium")]
    public async Task Report_dto_and_serialized_search_row_share_exact_machine_semantics(string action,string severity)
    {
        var data=new JsonObject { ["TaskName"]="\\Fixture",["Action"]=action };
        var row=Object("""{"id":77,"event_id":140,"provider_name":"Microsoft-Windows-TaskScheduler","channel":"Microsoft-Windows-TaskScheduler/Operational","server":"DC1","time_created_utc":"2026-07-18T10:00:00Z"}""");
        row["event_data_json"]=data.ToJsonString();
        var search=EventListProjection.Project(row);
        var reportRow=(JsonObject)row.DeepClone(); reportRow["event_db_id"]=77; reportRow["event_data"]=data;
        var report=await EventCatalogQuality.BuildReportEventDtoAsync(reportRow,Normalizer(),TestContext.Current.CancellationToken);
        foreach(string key in new[]{"final_security_severity","purpose_tier","assessment_confidence","noise_class","catalog_match","reasons","evidence_fields"}) Assert.True(JsonNode.DeepEquals(report[key],search[key]),key+": "+report[key]+" != "+search[key]);
        Assert.Equal(77,(int)report["event_db_id"]!); Assert.DoesNotContain("event_data_json",report.ToJsonString());
        Assert.Equal(severity,report["final_security_severity"]!.ToString());
        Assert.False(row.ContainsKey("event_data"));
    }

    [Fact] public void Compiled_risk_sql_binds_all_catalog_values_and_like_patterns()
    {
        var compiled=EventCatalogRiskSql.Compile([140]); string sql=(compiled.CaseSql+compiled.MatchedSql).ToLowerInvariant();
        Assert.DoesNotContain("microsoft-windows",sql); Assert.DoesNotContain("powershell",sql); Assert.Contains("like @catalog",sql);
        var values=compiled.Parameters.Values.Select(v=>v.ToString()!.ToLowerInvariant()).ToArray();
        Assert.Contains(values,v=>v.Contains("microsoft-windows-taskscheduler")); Assert.Contains(values,v=>v.Contains("powershell"));
        foreach(var parameter in compiled.Parameters) Assert.Contains("@"+parameter.Key,sql);
        Assert.Contains(values,v=>v=="%powershell%");
        var empty=EventCatalogRiskSql.Compile([]); Assert.Equal("(1 = 0)",empty.MatchedSql); Assert.True(empty.Exact);
    }
}
