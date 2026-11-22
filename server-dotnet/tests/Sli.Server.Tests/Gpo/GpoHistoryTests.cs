using System.Text.Json.Nodes;
using Sli.Server.Gpo;
using Xunit;
using static Sli.Server.Gpo.GpoJson;

namespace Sli.Server.Tests.Gpo;

public sealed class GpoHistoryTests
{
    static JsonObject Confirmation(string id,string? previous,string time,string coverage="complete")=>new() { ["manifest_id"]=id,["previous_manifest_id"]=previous,["domain_id"]=1,["family"]="gpo_v2",["observed_at"]=time,["coverage_state"]=coverage,["batch_id"]=new string('a',64),["record_count"]=0,["records_sha256"]=Hash(new JsonArray()) };
    [Fact] public void Coverage_reports_missing_pairs_schedule_gaps_retention_and_partial_sources()
    {
        var rows=new[]{Confirmation("a",null,"2026-10-01T00:00:00Z","partial"),Confirmation("c","wrong","2026-10-02T12:00:00Z")};var coverage=GpoChangeHistory.Coverage(rows,[1,2],Stamp("2026-09-30T00:00:00Z"),Stamp("2026-10-03T00:00:00Z"),Stamp("2026-10-01T00:00:00Z"));
        Assert.Equal("partial",coverage.Text("state"));Assert.Equal(new[]{"history_ends_earlier","history_gap","history_not_collected","history_starts_later","outside_retention","partial_snapshot_pair","snapshot_schedule_gap"},coverage["reasons"]!.AsArray().Select(x=>x!.ToString()));
    }
    [Fact] public async Task Exact_batch_digest_and_record_hash_are_verified_before_releasing_history()
    {
        string batch=new string('a',64);var payload=new JsonObject { ["object_id"]="synthetic-gpo",["kind"]="attribute_changed",["field"]="display_name" };
        string raw=payload.ToJsonString();string recordId=Hash(new JsonArray(batch,payload.DeepClone()));var rows=new List<JsonObject> { new() { ["record_id"]=recordId,["payload_json"]=raw } };
        var c=Confirmation("b","a","2026-10-01T12:00:00Z");c["record_count"]=1;c["records_sha256"]=Hash(new JsonArray(new JsonArray(recordId,raw)));
        async Task<List<JsonObject>> Read(string id,long domain,string family,DateTimeOffset observed,CancellationToken ct) { Assert.Equal(batch,id);Assert.Equal(1,domain);Assert.Equal("gpo_v2",family);Assert.Equal(Stamp("2026-10-01T12:00:00Z"),observed);await Task.CompletedTask;return rows; }
        var result=await GpoChangeHistory.ReadAsync([c],[1],Stamp("2026-10-01T00:00:00Z"),Stamp("2026-10-02T00:00:00Z"),Stamp("2026-01-01T00:00:00Z"),365,"",Read,TestContext.Current.CancellationToken);Assert.Single(result.Rows("items"));Assert.Equal("synthetic-gpo",result["items"]![0].Text("object_id"));
        rows[0]["payload_json"]="{}";await Assert.ThrowsAsync<InvalidDataException>(()=>GpoChangeHistory.ReadAsync([c],[1],Stamp("2026-10-01T00:00:00Z"),Stamp("2026-10-02T00:00:00Z"),Stamp("2026-01-01T00:00:00Z"),365,"",Read,TestContext.Current.CancellationToken));
    }
    [Fact]
    public async Task Policy_history_only_returns_matching_records_and_verified_values()
    {
        var confirmation=Confirmation("b","a","2026-10-01T12:00:00Z");
        string batch=confirmation.Text("batch_id");
        JsonObject Record(string policy,string after)
        {
            var payload=new JsonObject { ["object_type"]="gpo_setting",["object_id"]="synthetic-setting",
                ["related_object_id"]=policy,["kind"]="attribute_changed",["field"]="value_display",
                ["before_sha256"]=Hash(JsonValue.Create("900 seconds")),["after_sha256"]=Hash(JsonValue.Create("600 seconds")) };
            return new JsonObject { ["record_id"]=Hash(new JsonArray(batch,payload.DeepClone())),
                ["payload_json"]=payload.ToJsonString(),["before_value"]="900 seconds",["after_value"]=after };
        }
        var records=new List<JsonObject> { Record("synthetic-policy","incorrect value"),Record("synthetic-policy-other","600 seconds") };
        confirmation["record_count"]=records.Count;
        confirmation["records_sha256"]=Hash(new JsonArray(records.Select(row=>(JsonNode)new JsonArray(row.Text("record_id"),row.Text("payload_json"))).ToArray()));
        var result=await GpoChangeHistory.ReadAsync([confirmation],[1],Stamp("2026-10-01T00:00:00Z"),Stamp("2026-10-02T00:00:00Z"),
            Stamp("2026-01-01T00:00:00Z"),365,"",(_,_,_,_,_)=>Task.FromResult(records),TestContext.Current.CancellationToken,"synthetic-policy");
        var change=Assert.Single(result.Rows("items"));
        Assert.Equal("900 seconds",change.Text("before_value"));
        Assert.Null(change["after_value"]);
    }
}
