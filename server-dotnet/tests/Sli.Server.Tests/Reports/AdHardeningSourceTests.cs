using System.Text.Json.Nodes;
using Sli.Server.Reports;
using Sli.Server.Semantic.Detections;
using Sli.Server.Tests.Semantic;
using Xunit;

namespace Sli.Server.Tests.Reports;

public class AdHardeningSourceTests
{
    internal static readonly DateTimeOffset Now=DateTimeOffset.Parse("2026-01-01T00:00:00Z");
    internal static JsonObject Account(string key="fixture-user",bool spn=true)=>new(){["record_key"]=key,["identity"]=new JsonObject{["kind"]="ad_user",["object_sid"]="S-1-5-21-1-2-3-1100"},["attributes"]=new JsonObject{["sam_account_name"]=key,["user_account_control"]=512,["service_principal_names"]=spn?new JsonArray("HTTP/x"):new JsonArray()}};
    internal static JsonObject Snapshot()=>new(){["available"]=true,["domain_id"]=7L,["run_id"]="00000000-0000-0000-0000-000000000007",["observed_at_utc"]=D.Stamp(Now),["objects"]=new JsonArray(Account()),["edges"]=new JsonArray(),["complete"]=true};
    internal static JsonObject VerifiedRow(JsonObject record){var copy=(JsonObject)record.DeepClone();copy["observed_at_utc"]=D.Stamp(Now).Replace("+00:00","Z",StringComparison.Ordinal);return new(){["attributes_json"]=record.DeepClone(),["integrity_sha256"]=D.Hash(copy)};}
    [Fact]public async Task Empty_authorized_scope_does_not_read_database_and_latest_missing_family_does_not_fall_back()
    {
        var sql=new DetectionProducerTests.Sql();var empty=await AdHardeningSource.Load(sql,[],TestContext.Current.CancellationToken);Assert.Empty(sql.Queries);Assert.Empty(empty.Items);
        sql.SnapshotRun=new(){["domain_id"]=7L,["run_id"]=null};var data=await AdHardeningSource.Load(sql,[7],TestContext.Current.CancellationToken);Assert.False(data.Items.Single()["available"]!.GetValue<bool>());Assert.Single(sql.Queries);Assert.Equal("not_collected",D.Text(AdHardeningReport.Render(data,Now)["state"]));
    }
    [Fact]public async Task Exact_published_run_pins_hash_membership_validity_and_bounded_completeness()
    {
        var sql=new DetectionProducerTests.Sql{SnapshotRun=new(){["domain_id"]=7L,["run_id"]="00000000-0000-0000-0000-000000000007",["observed_at_utc"]=D.Stamp(Now),["mode"]="full",["sections"]=new JsonObject{["directory_accounts"]=new JsonObject{["status"]="complete",["record_count"]=1},["directory_group_graph"]=new JsonObject{["status"]="complete",["record_count"]=0}}},Entities=[VerifiedRow(Account())]};
        var data=await AdHardeningSource.Load(sql,[7],TestContext.Current.CancellationToken);Assert.True(data.Items.Single()["complete"]!.GetValue<bool>());Assert.Single(data.Items.Single()["objects"]!.AsArray());Assert.False(data.Truncated);Assert.Contains("s.payload_sha256",sql.Queries[0]);Assert.All(sql.Queries.Skip(1),q=>Assert.Contains("evidence.source_run_id=@run",q));Assert.All(sql.Queries.Skip(1),q=>Assert.Contains("v.valid_to_utc>@at",q));
        sql.Entities[0]["attributes_json"]!["attributes"]!["user_account_control"]=524800;data=await AdHardeningSource.Load(sql,[7],TestContext.Current.CancellationToken);Assert.Empty(data.Items.Single()["objects"]!.AsArray());Assert.False(data.Items.Single()["complete"]!.GetValue<bool>());
    }
    [Fact]public void Changed_record_cannot_impersonate_snapshot_at_same_time()
    {
        var original=VerifiedRow(Account());Assert.Single(AdHardeningSource.Verified([original],Now));original["attributes_json"]!["attributes"]!["user_account_control"]=524800;Assert.Empty(AdHardeningSource.Verified([original],Now));
    }
    [Fact]public void Python_utf8_hash_accepts_non_ascii_directory_labels()
    {
        var row=new JsonObject{["attributes_json"]=Account("служба 1С"),["integrity_sha256"]="886fced555b9671ba8e4b591e2582abd90f425fe5e593722e10a4717daf58c75"};Assert.Single(AdHardeningSource.Verified([row],Now));
    }
    [Theory][InlineData(0,true,"ok")][InlineData(2,true,"ok")][InlineData(3,true,"partial")][InlineData(-1,true,"partial")][InlineData(0,false,"partial")]
    public void Freshness_coverage_filters_and_localization(int age,bool complete,string state)
    {
        var snapshot=Snapshot();snapshot["observed_at_utc"]=D.Stamp(Now.AddDays(-age));snapshot["complete"]=complete;var data=new AdHardeningSnapshots([snapshot],false);var result=AdHardeningReport.Render(data,Now,true,"medium","FIXTURE-USER","qw.ad-hardening.spn-users");Assert.Equal(state,D.Text(result["state"]));var row=Assert.Single(result["collections"]!["ad_hardening"]!.AsArray());Assert.Contains("long password",D.Text(row!["what"]));Assert.NotEmpty(result["limitations"]!.AsArray());
        Assert.Empty(AdHardeningReport.Render(data,Now,query:"absent")["collections"]!["ad_hardening"]!.AsArray());
    }
    [Fact]public void Projection_hides_identity_and_technical_fields_including_translated_parameters()
    {
        var result=AdHardeningReport.Render(new([Snapshot()],false),Now,fieldAllowed:(_,_)=>false);string text=result.ToJsonString();Assert.DoesNotContain("fixture-user",text);Assert.DoesNotContain("00000000-0000-0000-0000-000000000007",text);Assert.DoesNotContain("domain_id",text);Assert.NotEmpty(result["collections"]!["ad_hardening"]!.AsArray());
    }
    [Theory][InlineData(false)][InlineData(true)]
    public void All_checks_have_simple_text_and_single_laps_summary(bool english)
    {
        foreach(string check in new[]{"spn_users","rc4","unconstrained","constrained","laps","old_service_password","privileged_nonexpiring","admin_group_size","inactive_privileged"})foreach(string field in new[]{"title","what","why","action"}){string text=DetectionMessages.Text("security.problems.ad_hardening."+check+"."+field,english);Assert.NotEmpty(text);Assert.DoesNotContain("AI-assisted",text);Assert.DoesNotContain("ИИ",text);}
        var snapshot=Snapshot();var account=Account("fixture-computer",false);account["identity"]!["kind"]="ad_computer";account["attributes"]!["laps_password_expiration_status"]="schema_absent";account["attributes"]!["legacy_laps_password_expiration_status"]="not_set";snapshot["objects"]=new JsonArray(account);
        var result=AdHardeningReport.Render(new([snapshot],false),Now,english);var row=Assert.Single(result["collections"]!["ad_hardening"]!.AsArray());Assert.Equal(english?"LAPS was not found on any computer.":"LAPS не найден ни на одном компьютере.",D.Text(row!["what"]));Assert.Empty(row["objects"]!.AsArray());
    }
}
